use std::time::Duration;

use flurl::FlUrlResponse;
use my_http_client::RequestBodyStream;
use tokio::sync::mpsc::Receiver;

use super::{S3Error, S3Region};

/// `x-amz-content-sha256` value that tells S3 the payload is not covered by the
/// signature. Required for a streamed body: the header has to be signed before the
/// first byte is sent, and the hash of a payload that is still being produced cannot
/// be known at that point.
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

pub struct S3Client {
    pub access_key: String,
    pub secret_key: String,
    /// Signed into the credential scope of every request, and stated again in the
    /// `LocationConstraint` of [`Self::create_bucket`]. `"eu-west-1".into()` or
    /// [`S3Region::from_str`] turns configuration into one.
    pub region: S3Region,
    pub endpoint: String,
}

impl S3Client {
    /// Uploads an object that is already fully in memory.
    ///
    /// Peak memory is the size of `content` (plus whatever the caller holds), so this
    /// is for small objects. Use [`Self::upload_streamed`] for anything whose size is
    /// not bounded by construction.
    ///
    /// `upload_timeout` bounds the whole request, sending `content` included - the same
    /// meaning it has in [`Self::upload_streamed`]. `FlUrl`'s own default is 10 seconds,
    /// which is a limit on the *upload*, not on the wait for the response, so a body
    /// that takes longer than that to push out fails however healthy the server is.
    ///
    /// Unlike the streamed variant this one *is* covered by the signature
    /// (`x-amz-content-sha256` is the real hash of `content`) and is retried
    /// automatically up to 3 times, because a `Vec<u8>` can be sent again.
    pub async fn upload(
        &self,
        bucket_name: &str,
        key: &str,
        content: Vec<u8>,
        upload_timeout: Duration,
    ) -> Result<(), S3Error> {
        let fl_url = flurl::FlUrl::new(self.endpoint.as_str())
            .append_path_segment(bucket_name)
            .append_path_segment(key)
            .set_timeout(upload_timeout)
            .with_retries(3);

        let fl_url = super::utils::sign_request(self, fl_url, "PUT", content.as_slice())?;

        let response = fl_url
            .put(flurl::body::HttpRequestBody::from_raw_data(content, None))
            .await?;

        expect_success(response).await
    }

    /// Uploads an object from a channel, so that peak memory is one chunk instead of
    /// the size of the object.
    ///
    /// The caller owns the reading: push chunks into the `Sender` at whatever pace the
    /// source produces them, and **drop the `Sender` after the last one** - that is how
    /// the body is terminated. The channel's capacity is the backpressure, so a
    /// `channel(4)` with 256 KiB chunks keeps at most ~1 MiB in flight regardless of
    /// how large the object is.
    ///
    /// `content_length` must equal the sum of all chunk lengths **exactly**. It is sent
    /// as `Content-Length` (not chunked, because SigV4 requests are not accepted
    /// chunked), and HTTP/1.1 gives no way to correct it afterwards: too few bytes make
    /// the message incomplete and the request fails, too many would be read as the next
    /// request on the same connection. Take the length and the data from one source -
    /// a file's metadata and that same file handle - never compute it twice.
    ///
    /// `upload_timeout` bounds the **whole** transfer, not just the wait for the
    /// response head. `FlUrl`'s default is 10 seconds, which silently kills any real
    /// upload, which is why this is a required parameter rather than a default.
    ///
    /// # Failure and retries
    ///
    /// The request is attempted **exactly once**: `FlUrl::with_retries` is ignored for
    /// a streamed body because the payload is consumed as it is sent. When it fails,
    /// the channel is dropped, so the sending side starts getting "channel closed" with
    /// no reason attached - the reason comes from *this* function's return value, so
    /// the caller must always await it and not infer the outcome from the send side.
    ///
    /// Ask [`S3Error::is_retryable`] whether repeating makes sense; retrying is safe
    /// because `PutObject` is atomic, but the payload has to be rebuilt from the start.
    /// [`Self::upload_streamed_with_retries`] does that loop.
    ///
    /// # Signature
    ///
    /// The payload is sent as `UNSIGNED-PAYLOAD`: the signature covers the headers, the
    /// verb and the path, but not the body, because the body's hash is not knowable
    /// before the body is produced. Transport integrity therefore rests on TLS - use an
    /// `https` endpoint. AWS and Ceph (Hetzner Object Storage) both accept this.
    ///
    /// ```no_run
    /// # async fn doc(s3: &my_s3::S3Client, path: &str) -> Result<(), my_s3::S3Error> {
    /// use tokio::io::AsyncReadExt;
    ///
    /// let content_length = tokio::fs::metadata(path).await.unwrap().len() as usize;
    /// let mut file = tokio::fs::File::open(path).await.unwrap();
    ///
    /// // 4 chunks of backpressure: the reader blocks once the socket is 4 behind
    /// let (sender, receiver) = tokio::sync::mpsc::channel(4);
    ///
    /// tokio::spawn(async move {
    ///     let mut buffer = vec![0u8; 256 * 1024];
    ///     loop {
    ///         let read = match file.read(&mut buffer).await {
    ///             Ok(0) => break,
    ///             Ok(read) => read,
    ///             Err(_) => break,
    ///         };
    ///         // Err means the upload is already over - stop, the reason comes from
    ///         // the upload_streamed() call itself
    ///         if sender.send(buffer[..read].to_vec()).await.is_err() {
    ///             break;
    ///         }
    ///     }
    ///     // dropping the sender here is what terminates the body
    /// });
    ///
    /// let result = s3
    ///     .upload_streamed(
    ///         "my-bucket",
    ///         "archives/backup.tar",
    ///         receiver,
    ///         content_length,
    ///         std::time::Duration::from_secs(600),
    ///     )
    ///     .await;
    ///
    /// if let Err(err) = &result {
    ///     if err.is_retryable() {
    ///         // rebuild the reader from the beginning and call again
    ///     }
    /// }
    ///
    /// result
    /// # }
    /// ```
    pub async fn upload_streamed(
        &self,
        bucket_name: &str,
        key: &str,
        body: Receiver<Vec<u8>>,
        content_length: usize,
        upload_timeout: Duration,
    ) -> Result<(), S3Error> {
        // No `with_retries`: it is ignored on this path, and setting it would suggest
        // otherwise at the call site.
        let fl_url = flurl::FlUrl::new(self.endpoint.as_str())
            .append_path_segment(bucket_name)
            .append_path_segment(key)
            .set_timeout(upload_timeout);

        let fl_url =
            super::utils::sign_request_with_payload_hash(self, fl_url, "PUT", UNSIGNED_PAYLOAD)?;

        let response = fl_url
            .put_request_streamed(RequestBodyStream::from(body), Some(content_length))
            .await?;

        expect_success(response).await
    }

    /// [`Self::upload_streamed`] with the retry loop the streamed path cannot do on
    /// its own.
    ///
    /// `new_body` is called once per attempt and must hand back a channel that replays
    /// the payload **from the beginning** - reopen the file, re-run the query. The
    /// closure returning the `Receiver` (rather than this function creating it) is what
    /// makes that requirement impossible to miss: there is nowhere to accidentally
    /// resume a half-drained source.
    ///
    /// Stops at the first error that [`S3Error::is_retryable`] rejects, and returns the
    /// last error once the attempts run out. Note that a timeout counts as retryable,
    /// so an `upload_timeout` that is simply too small for the object costs
    /// `max_retries + 1` full attempts before surfacing.
    ///
    /// ```no_run
    /// # async fn doc(s3: &my_s3::S3Client, path: &'static str, len: usize)
    /// # -> Result<(), my_s3::S3Error> {
    /// use tokio::io::AsyncReadExt;
    ///
    /// s3.upload_streamed_with_retries(
    ///     "my-bucket",
    ///     "archives/backup.tar",
    ///     len,
    ///     std::time::Duration::from_secs(600),
    ///     3,
    ///     || {
    ///         let (sender, receiver) = tokio::sync::mpsc::channel(4);
    ///
    ///         // A fresh handle per attempt: the previous one is half-drained
    ///         tokio::spawn(async move {
    ///             let mut file = tokio::fs::File::open(path).await.unwrap();
    ///             let mut buffer = vec![0u8; 256 * 1024];
    ///             while let Ok(read) = file.read(&mut buffer).await {
    ///                 if read == 0 || sender.send(buffer[..read].to_vec()).await.is_err() {
    ///                     break;
    ///                 }
    ///             }
    ///         });
    ///
    ///         receiver
    ///     },
    /// )
    /// .await
    /// # }
    /// ```
    pub async fn upload_streamed_with_retries<TNewBody>(
        &self,
        bucket_name: &str,
        key: &str,
        content_length: usize,
        upload_timeout: Duration,
        max_retries: usize,
        mut new_body: TNewBody,
    ) -> Result<(), S3Error>
    where
        TNewBody: FnMut() -> Receiver<Vec<u8>>,
    {
        let mut attempt = 0;

        loop {
            let result = self
                .upload_streamed(bucket_name, key, new_body(), content_length, upload_timeout)
                .await;

            let err = match result {
                Ok(()) => return Ok(()),
                Err(err) => err,
            };

            if attempt >= max_retries || !err.is_retryable() {
                return Err(err);
            }

            attempt += 1;
        }
    }

    pub async fn download_file(&self, bucket_name: &str, key: &str) -> Result<Vec<u8>, S3Error> {
        self.download_internal(bucket_name, key, None).await
    }

    /// Downloads a byte range of an object.
    ///
    /// `start` and `end` are **inclusive** byte offsets, following the HTTP `Range`
    /// header semantics (RFC 7233): `start = 0, end = Some(99)` returns the first
    /// 100 bytes. Pass `end = None` to read from `start` to the end of the object.
    ///
    /// Returns [`S3Error::RangeNotSatisfiable`] if `start` is at or beyond the
    /// object size, and an error if the server ignores the `Range` header and
    /// responds with the full object instead of a partial one.
    pub async fn download_file_range(
        &self,
        bucket_name: &str,
        key: &str,
        start: u64,
        end: Option<u64>,
    ) -> Result<Vec<u8>, S3Error> {
        if let Some(end) = end
            && end < start
        {
            return Err(S3Error::Other(format!(
                "Invalid range: end ({}) < start ({})",
                end, start
            )));
        }

        self.download_internal(bucket_name, key, Some((start, end)))
            .await
    }

    async fn download_internal(
        &self,
        bucket_name: &str,
        key: &str,
        range: Option<(u64, Option<u64>)>,
    ) -> Result<Vec<u8>, S3Error> {
        let fl_url = flurl::FlUrl::new(self.endpoint.as_str())
            .append_path_segment(bucket_name)
            .append_path_segment(key)
            .with_retries(3);

        let fl_url = super::utils::sign_request(self, fl_url, "GET", [].as_slice())?;

        // `Range` is not an `x-amz-*` header and is not in SignedHeaders, so adding it
        // after signing does not invalidate the signature.
        let fl_url = match range {
            Some((start, Some(end))) => {
                fl_url.with_header("Range", format!("bytes={}-{}", start, end))
            }
            Some((start, None)) => fl_url.with_header("Range", format!("bytes={}-", start)),
            None => fl_url,
        };

        let fl_url_response = fl_url.get().await?;

        let status_code = fl_url_response.get_status_code();

        // A plain download expects 200; a range request expects 206 Partial Content.
        // If a range was requested but the server replies 200, it ignored the Range
        // header and returned the whole object - surface that rather than silently
        // handing back far more data than asked for.
        let expected = if range.is_some() { 206 } else { 200 };
        if status_code == expected {
            return Ok(fl_url_response.receive_body().await?);
        }

        if range.is_some() && status_code == 416 {
            return Err(S3Error::RangeNotSatisfiable);
        }

        if range.is_some() && status_code == 200 {
            return Err(S3Error::Other(
                "Server ignored the Range header and returned the full object (200 instead of 206)"
                    .to_string(),
            ));
        }

        let body = fl_url_response.receive_body().await?;
        Err(detect_error(status_code, &body))
    }

    /// Deletes an object.
    ///
    /// S3 answers a successful `DeleteObject` with **204 No Content** and no body, and
    /// deleting a key that is not there is also a success - the operation is
    /// idempotent, so a missing key is not reported as [`S3Error::KeyNotFound`].
    pub async fn delete_file(&self, bucket_name: &str, key: &str) -> Result<(), S3Error> {
        let fl_url = flurl::FlUrl::new(self.endpoint.as_str())
            .append_path_segment(bucket_name)
            .append_path_segment(key)
            .with_retries(3);

        let fl_url = super::utils::sign_request(self, fl_url, "DELETE", [].as_slice())?;

        let fl_url_response = fl_url.delete().await?;

        expect_success(fl_url_response).await
    }

    /// Creates a bucket in [`Self::region`] - the same region the request is signed
    /// for.
    ///
    /// The bucket is placed by the `LocationConstraint` in the body, which S3 requires
    /// to agree with the region of the endpoint the request went to. `us-east-1` is the
    /// one region stated by *not* sending the element - AWS rejects naming it
    /// explicitly, and an absent body already means exactly it.
    ///
    /// Re-creating a bucket we already own is [`S3Error::BucketAlreadyOwnedByYou`] -
    /// see [`Self::create_bucket_if_not_exists`] for treating that as success, or
    /// [`S3Error::bucket_name_is_taken`] to decide it at the call site.
    pub async fn create_bucket(&self, bucket_name: &str) -> Result<(), S3Error> {
        let fl_url = flurl::FlUrl::new(self.endpoint.as_str())
            .append_path_segment(bucket_name)
            .with_retries(3);

        let configuration = create_bucket_configuration(&self.region);

        // The payload hash is part of the signature, so what is signed here has to be
        // the very bytes `put` sends below. Signing an empty payload and then sending
        // the XML answers 403 SignatureDoesNotMatch, which reads as a credentials
        // problem rather than as the mismatch it is.
        let fl_url = super::utils::sign_request(
            self,
            fl_url,
            "PUT",
            configuration.as_deref().unwrap_or_default(),
        )?;

        let body = match configuration {
            Some(configuration) => {
                flurl::body::HttpRequestBody::from_raw_data(configuration, Some("application/xml"))
            }
            None => flurl::body::HttpRequestBody::empty(),
        };

        let fl_url_response = fl_url.put(body).await?;

        expect_success(fl_url_response).await
    }

    /// [`Self::create_bucket`], but a bucket that is **already ours** is success rather
    /// than an error - for the ensure-the-bucket-is-there call that runs before every
    /// use of it, where the second run must not fail differently from the first.
    ///
    /// Only [`S3Error::BucketAlreadyOwnedByYou`] is absorbed.
    /// [`S3Error::BucketAlreadyExists`] - the name is held by *another account* - stays
    /// an error, because the bucket that exists is then not the one the caller is about
    /// to write to.
    pub async fn create_bucket_if_not_exists(&self, bucket_name: &str) -> Result<(), S3Error> {
        match self.create_bucket(bucket_name).await {
            Err(err) if err.is_bucket_already_owned_by_you() => Ok(()),
            result => result,
        }
    }
}

/// The `CreateBucket` body that places the bucket, or `None` when the region is stated
/// by sending no body at all.
///
/// `CreateBucket` names its region **twice** - the endpoint the request is sent to, and
/// this element - and S3 requires the two to agree. An absent body is not "the region
/// does not matter", it is literally `us-east-1`, S3's historical default; sending none
/// to any other regional endpoint is a contradiction, and AWS refuses to guess:
///
/// ```text
/// 400 IllegalLocationConstraintException
/// The unspecified location constraint is incompatible for the region specific
/// endpoint this request was sent to.
/// ```
///
/// `us-east-1` is therefore the one region that must **not** be named: AWS rejects an
/// explicit `LocationConstraint` of `us-east-1`, so it keeps the empty body. An empty
/// region is the same statement - `<LocationConstraint></LocationConstraint>` would
/// only be a malformed way of saying the default.
fn create_bucket_configuration(region: &S3Region) -> Option<Vec<u8>> {
    if region.is_empty() || region.is_us_east_1() {
        return None;
    }

    // The xmlns is what every AWS SDK sends and what the AWS docs show. Nothing rejects
    // the element without it, but nothing rejects it with it either, so it is the safer
    // of the two against S3-compatible implementations.
    let configuration = format!(
        "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>{}</LocationConstraint></CreateBucketConfiguration>",
        region.as_str()
    );

    Some(configuration.into_bytes())
}

/// Any 2xx is a success.
///
/// Checking `== 200` is wrong for a whole class of S3 operations: `DeleteObject`
/// answers **204 No Content**, so every delete used to come back as an error and a
/// hard delete silently removed nothing.
fn is_success(status_code: u16) -> bool {
    (200..300).contains(&status_code)
}

async fn expect_success(response: FlUrlResponse) -> Result<(), S3Error> {
    read_success_body(response).await?;
    Ok(())
}

async fn read_success_body(response: FlUrlResponse) -> Result<Vec<u8>, S3Error> {
    let status_code = response.get_status_code();

    // Read the body either way: on success it is the payload, on failure it carries
    // `<Error><Code>`, which is the only reliable way to tell the failures apart.
    let body = response.receive_body().await?;

    if is_success(status_code) {
        return Ok(body);
    }

    Err(detect_error(status_code, &body))
}

/// Maps a non-2xx answer onto a typed error.
///
/// Prefers the `<Error><Code>` in the body over the status code, because the status
/// alone is ambiguous - 404 is both `NoSuchKey` and `NoSuchBucket`, 409 is both
/// `BucketAlreadyExists` and `BucketAlreadyOwnedByYou`. Falls back to the status when
/// the body is absent or is not S3's XML (a proxy's HTML page, an empty body on a HEAD).
fn detect_error(status_code: u16, body: &[u8]) -> S3Error {
    let error_code = crate::xml::read_node_text(body, "Error/Code");

    if let Some(error_code) = error_code.as_deref()
        && let Some(err) = map_error_code(error_code)
    {
        return err;
    }

    if error_code.is_none() {
        match status_code {
            404 => return S3Error::KeyNotFound,
            416 => return S3Error::RangeNotSatisfiable,
            _ => {}
        }
    }

    S3Error::UnexpectedStatusCode {
        status_code,
        error_code,
        body: String::from_utf8_lossy(body).into_owned(),
    }
}

fn map_error_code(error_code: &str) -> Option<S3Error> {
    let result = match error_code {
        "BucketAlreadyExists" => S3Error::BucketAlreadyExists,
        "BucketAlreadyOwnedByYou" => S3Error::BucketAlreadyOwnedByYou,
        "NoSuchBucket" => S3Error::BucketNotFound,
        "NoSuchKey" => S3Error::KeyNotFound,
        "NoSuchUpload" => S3Error::NoSuchUpload,
        "EntityTooSmall" => S3Error::EntityTooSmall,
        "InvalidRange" => S3Error::RangeNotSatisfiable,
        _ => return None,
    };

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_returns_204_which_is_a_success() {
        assert!(is_success(204));
        assert!(is_success(200));
        assert!(is_success(206));
        assert!(!is_success(404));
        assert!(!is_success(300));
    }

    /// Anything but `us-east-1` has to say where the bucket goes, or the regional
    /// endpoint answers 400 IllegalLocationConstraintException.
    #[test]
    fn a_regional_bucket_states_where_it_goes() {
        let configuration = create_bucket_configuration(&S3Region::AwsEuWest1).unwrap();

        assert_eq!(
            String::from_utf8(configuration).unwrap(),
            "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>"
        );
    }

    /// The inverse rule, and the reason this cannot simply always send the element:
    /// AWS rejects an explicit `LocationConstraint` of `us-east-1`. The empty body *is*
    /// how that region is stated.
    #[test]
    fn us_east_1_is_stated_by_sending_nothing() {
        assert!(create_bucket_configuration(&S3Region::AwsUsEast1).is_none());
        // However the region was built - the rule follows the string, not the variant.
        assert!(create_bucket_configuration(&S3Region::from_str("us-east-1")).is_none());
        // A region that was never configured means the default, not an empty element.
        assert!(create_bucket_configuration(&S3Region::from_str("")).is_none());
    }

    /// Non-AWS endpoints name their regions freely, and the value has to reach the body
    /// verbatim - it is the same string the signature's credential scope is built from.
    /// Hetzner documents creating a bucket with `--region fsn1`, so `fsn1` is what its
    /// `LocationConstraint` has to say.
    #[test]
    fn a_non_aws_region_is_passed_through_verbatim() {
        for region in [
            S3Region::HetznerFsn1,
            S3Region::Other("some-private-ceph".to_string()),
        ] {
            let configuration = create_bucket_configuration(&region).unwrap();

            assert!(
                String::from_utf8(configuration).unwrap().contains(
                    format!(
                        "<LocationConstraint>{}</LocationConstraint>",
                        region.as_str()
                    )
                    .as_str()
                )
            );
        }
    }

    #[test]
    fn detect_bucket_exists_error() {
        let xml = "<Error><Code>BucketAlreadyExists</Code><Message>The requested bucket name is not available.</Message><Resource>chat-bot-files-dev</Resource><RequestId>2fd9b10e5df517b3be17b5df4fe3d8c4</RequestId></Error>";

        assert!(detect_error(409, xml.as_bytes()).is_bucket_already_exists());
    }

    /// Recreating a bucket we already own answers 409 like `BucketAlreadyExists` does,
    /// so only the body tells them apart.
    #[test]
    fn detect_bucket_already_owned_by_you() {
        let xml = "<Error><Code>BucketAlreadyOwnedByYou</Code><Message>Your previous request to create the named bucket succeeded and you already own it.</Message></Error>";

        let err = detect_error(409, xml.as_bytes());

        assert!(err.is_bucket_already_owned_by_you());
        assert!(err.bucket_name_is_taken());
        assert!(!err.is_retryable());
    }

    #[test]
    fn detect_no_such_key() {
        let xml = "<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>";

        assert!(detect_error(404, xml.as_bytes()).is_key_not_found());
    }

    /// 404 is `NoSuchBucket` as often as it is `NoSuchKey`; falling back to the status
    /// code alone would report a missing bucket as a missing key.
    #[test]
    fn detect_no_such_bucket_is_not_reported_as_a_missing_key() {
        let xml = "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist.</Message></Error>";

        let err = detect_error(404, xml.as_bytes());

        assert!(err.is_bucket_not_found());
        assert!(!err.is_key_not_found());
    }

    /// A 404 with no usable body still has to be typed - a HEAD has no body at all.
    #[test]
    fn bare_404_falls_back_to_key_not_found() {
        assert!(detect_error(404, &[]).is_key_not_found());
        assert!(detect_error(404, b"<html>Not Found</html>").is_key_not_found());
    }

    #[test]
    fn unknown_error_code_keeps_the_status_and_the_code() {
        let xml = "<Error><Code>SomethingBrandNew</Code><Message>nope</Message></Error>";

        let err = detect_error(400, xml.as_bytes());

        assert_eq!(err.get_status_code(), Some(400));
        match &err {
            S3Error::UnexpectedStatusCode { error_code, .. } => {
                assert_eq!(error_code.as_deref(), Some("SomethingBrandNew"));
            }
            _ => panic!("expected UnexpectedStatusCode, got {:?}", err),
        }
        assert!(!err.is_retryable());
    }

    /// The status code has to survive as a number so that a retry decision does not
    /// come from parsing a message.
    #[test]
    fn server_side_failures_are_retryable() {
        assert!(detect_error(500, &[]).is_retryable());
        assert!(detect_error(503, &[]).is_retryable());
        assert!(detect_error(429, &[]).is_retryable());

        assert!(!detect_error(400, &[]).is_retryable());
        assert!(!detect_error(403, &[]).is_retryable());
    }

    /// S3 asks for a retry by name, on a status that would otherwise look final.
    #[test]
    fn slow_down_is_retryable_whatever_the_status() {
        let xml = "<Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message></Error>";

        assert!(detect_error(400, xml.as_bytes()).is_retryable());
    }

    /// The old rendering is preserved so a caller still matching on the message keeps
    /// working while it migrates to `get_status_code()`.
    #[test]
    fn display_keeps_the_historical_status_code_shape() {
        let err = detect_error(418, b"teapot");

        assert_eq!(err.to_string(), "Status Code: 418. Err: teapot");
    }
}
