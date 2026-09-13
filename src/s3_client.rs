use std::time::Duration;

use flurl::FlUrlResponse;
use my_http_client::RequestBodyStream;
use tokio::sync::mpsc::Receiver;

use super::{S3DownloadStream, S3Error, S3ListObjectsPage, S3ListObjectsRequest, S3Region};

/// `x-amz-content-sha256` value that tells S3 the payload is not covered by the
/// signature. Required for a streamed body: the header has to be signed before the
/// first byte is sent, and the hash of a payload that is still being produced cannot
/// be known at that point.
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// Marks every line of the console trace, so it can be told apart from - and grepped
/// out of - whatever else the process writes to stdout.
const DEBUG_PREFIX: &str = "[my-s3]";

/// `FlUrl::append_query_param` takes `Option<impl Into<StrOrString>>`, so a bare `None`
/// leaves the value type unresolved. This names it once instead of at every call site.
const NO_VALUE: Option<&str> = None;

pub struct S3Client {
    pub access_key: String,
    pub secret_key: String,
    /// Signed into the credential scope of every request, and stated again in the
    /// `LocationConstraint` of [`Self::create_bucket`]. `"eu-west-1".into()` or
    /// [`S3Region::from_str`] turns configuration into one.
    pub region: S3Region,
    pub endpoint: String,
    /// Off unless [`Self::debug_to_console`] turned it on.
    debug_to_console: bool,
}

impl S3Client {
    pub fn new(
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        region: impl Into<S3Region>,
        endpoint: impl Into<String>,
    ) -> Self {
        Self {
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            region: region.into(),
            endpoint: endpoint.into(),
            debug_to_console: false,
        }
    }

    /// Traces every request this client makes to stdout.
    ///
    /// The request is printed as it is about to go out - verb, url, and the size of the
    /// body. The **answer** is printed in full only when it failed, because that body
    /// is the `<Error><Code>` that says why; a successful one is printed as a size,
    /// since it is the object that was just downloaded and nobody wants it on the
    /// console.
    ///
    /// The same asymmetry applies to the request: a control body small enough to be the
    /// point (the `CreateBucket` location constraint) is shown, an object payload is
    /// shown as a size.
    ///
    /// `Authorization` is deliberately never printed - it carries the access key id and
    /// the request's signature.
    ///
    /// ```no_run
    /// # fn doc() -> my_s3::S3Client {
    /// my_s3::S3Client::new(
    ///     "access-key",
    ///     "secret-key",
    ///     "fsn1",
    ///     "https://fsn1.your-objectstorage.com",
    /// )
    /// .debug_to_console()
    /// # }
    /// ```
    pub fn debug_to_console(mut self) -> Self {
        self.debug_to_console = true;
        self
    }
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

        let response = self
            .send_put(
                fl_url,
                flurl::body::HttpRequestBody::from_raw_data(content, None),
            )
            .await?;

        self.expect_success(response).await
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

        let response = self
            .send_put_streamed(fl_url, RequestBodyStream::from(body), content_length)
            .await?;

        self.expect_success(response).await
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

        let fl_url_response = self.send_get(fl_url).await?;

        let status_code = fl_url_response.get_status_code();

        // A plain download expects 200; a range request expects 206 Partial Content.
        // If a range was requested but the server replies 200, it ignored the Range
        // header and returned the whole object - surface that rather than silently
        // handing back far more data than asked for.
        let expected = if range.is_some() { 206 } else { 200 };
        if status_code == expected {
            let body = fl_url_response.receive_body().await?;
            self.trace_response(status_code, Some(&body));
            return Ok(body);
        }

        if range.is_some() && status_code == 416 {
            self.trace_response(status_code, None);
            return Err(S3Error::RangeNotSatisfiable);
        }

        if range.is_some() && status_code == 200 {
            // The body is deliberately left unread: it is the whole object, which is
            // exactly what was not asked for.
            self.trace_response(status_code, None);
            return Err(S3Error::Other(
                "Server ignored the Range header and returned the full object (200 instead of 206)"
                    .to_string(),
            ));
        }

        let body = fl_url_response.receive_body().await?;
        self.trace_response(status_code, Some(&body));
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

        let fl_url_response = self.send_delete(fl_url).await?;

        self.expect_success(fl_url_response).await
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

        let fl_url_response = self.send_put(fl_url, body).await?;

        self.expect_success(fl_url_response).await
    }

    /// Asks the storage which region a bucket is actually in - `GET /{bucket}?location`.
    ///
    /// This answers the question [`Self::create_bucket`] gets wrong loudly: the region
    /// is stated both by the endpoint and by the `LocationConstraint`, and when the two
    /// disagree the answer is a `400`, not a bucket. This is how to see what the storage
    /// thinks, rather than what the configuration says.
    ///
    /// `us-east-1` comes back as an **empty** constraint - AWS states the default region
    /// by omitting it, the same asymmetry `CreateBucket` has - and is reported here as
    /// [`S3Region::AwsUsEast1`] rather than as an empty region.
    ///
    /// A region this crate does not have a variant for comes back as
    /// [`S3Region::Other`], carried verbatim.
    pub async fn get_bucket_location(&self, bucket_name: &str) -> Result<S3Region, S3Error> {
        let fl_url = flurl::FlUrl::new(self.endpoint.as_str())
            .append_path_segment(bucket_name)
            .append_query_param("location", NO_VALUE)
            .with_retries(3);

        // `?location` is a valueless flag, and it is part of the canonical request:
        // SigV4 canonicalises it to `location=`, which is also how the server reads it
        // off the wire. Signing has to happen after it is appended.
        let fl_url = super::utils::sign_request(self, fl_url, "GET", [].as_slice())?;

        let response = self.send_get(fl_url).await?;

        let body = self.read_success_body(response).await?;

        parse_bucket_location(&body)
    }

    /// Whether the bucket is there and reachable with these credentials -
    /// `HEAD /{bucket}`.
    ///
    /// A `404` is `Ok(false)`: "not there" is an answer, not a failure. A `403` stays an
    /// error, because it means either that the name belongs to another account or that
    /// these credentials are wrong, and collapsing both into "it exists" would report a
    /// bad key as a healthy bucket.
    ///
    /// The answer to a `HEAD` carries **no body**, so a failure here has no
    /// `<Error><Code>` to be typed from - the status code is all there is.
    pub async fn check_if_bucket_exists(&self, bucket_name: &str) -> Result<bool, S3Error> {
        let fl_url = flurl::FlUrl::new(self.endpoint.as_str())
            .append_path_segment(bucket_name)
            .with_retries(3);

        let fl_url = super::utils::sign_request(self, fl_url, "HEAD", [].as_slice())?;

        let response = self.send_head(fl_url).await?;

        let status_code = response.get_status_code();

        // Nothing to read: a HEAD answer has no body by definition.
        self.trace_response(status_code, None);

        if is_success(status_code) {
            return Ok(true);
        }

        if status_code == 404 {
            return Ok(false);
        }

        Err(detect_error(status_code, &[]))
    }

    /// One page of a bucket's contents - `GET /{bucket}?list-type=2`.
    ///
    /// With a `delimiter` this is a directory listing: `common_prefixes` are the
    /// folders, `objects` are the files at this level. Without one it is a flat walk of
    /// every key under the prefix.
    ///
    /// A page is not the whole bucket. S3 caps a page at 1000 entries and may answer
    /// with fewer for reasons of its own, so
    /// [`S3ListObjectsPage::next_continuation_token`] - not the number of entries that
    /// came back - is what says whether to ask again:
    ///
    /// ```no_run
    /// # async fn doc(s3: &my_s3::S3Client) -> Result<(), my_s3::S3Error> {
    /// let mut token = None;
    ///
    /// loop {
    ///     let page = s3
    ///         .list_objects_v2(
    ///             "my-bucket",
    ///             my_s3::S3ListObjectsRequest {
    ///                 prefix: Some("photos/"),
    ///                 delimiter: Some("/"),
    ///                 continuation_token: token.as_deref(),
    ///                 ..Default::default()
    ///             },
    ///         )
    ///         .await?;
    ///
    ///     // ... use page.common_prefixes and page.objects ...
    ///
    ///     token = page.next_continuation_token;
    ///     if token.is_none() {
    ///         break;
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The `prefix` and `delimiter` have to be repeated unchanged on every page -
    /// a continuation token resumes a listing, it does not describe one.
    ///
    /// # Why the query is built by hand
    ///
    /// The parameters are URI-encoded here and appended as a raw ending rather than
    /// through `FlUrl::append_query_param`, because `FlUrl` encodes a query by the
    /// `x-www-form-urlencoded` rule and SigV4 needs the RFC 3986 one. The difference is
    /// a space (`+` versus `%20`), and a `prefix` with a space in it would otherwise be
    /// both mis-signed and mis-read. `utils::encode_uri_component` is where the whole
    /// argument lives.
    pub async fn list_objects_v2(
        &self,
        bucket_name: &str,
        request: S3ListObjectsRequest<'_>,
    ) -> Result<S3ListObjectsPage, S3Error> {
        // `max-keys` is a number in the request and a string on the wire; it has to
        // outlive the borrow the query builder takes.
        let max_keys = request.max_keys.map(|max_keys| max_keys.to_string());

        let mut query = String::from("list-type=2");
        super::utils::append_query_param(&mut query, "prefix", request.prefix);
        super::utils::append_query_param(&mut query, "delimiter", request.delimiter);
        super::utils::append_query_param(
            &mut query,
            "continuation-token",
            request.continuation_token,
        );
        super::utils::append_query_param(&mut query, "max-keys", max_keys.as_deref());

        // Path and query in one raw ending. Appending the bucket as a path segment and
        // the query raw would work too, except that `append_raw_ending` forces a `/`
        // ahead of whatever it is given - the request target would become
        // `/bucket/?list-type=2`, and a trailing slash is one more thing for an
        // S3-compatible implementation to disagree about. A legal bucket name is
        // `[a-z0-9.-]`, every character of which URI-encodes to itself, so encoding it
        // costs nothing and keeps an illegal one signed exactly as it is sent.
        let mut path_and_query = String::with_capacity(bucket_name.len() + query.len() + 2);
        path_and_query.push('/');
        super::utils::encode_uri_component(bucket_name, &mut path_and_query);
        path_and_query.push('?');
        path_and_query.push_str(query.as_str());

        let fl_url = flurl::FlUrl::new(self.endpoint.as_str())
            .append_raw_ending_to_url(path_and_query)
            .with_retries(3);

        // After the whole url is built, as always: the query is part of the canonical
        // request.
        let fl_url = super::utils::sign_request(self, fl_url, "GET", [].as_slice())?;

        let response = self.send_get(fl_url).await?;

        let body = self.read_success_body(response).await?;

        crate::list_objects::parse_list_objects_v2(&body)
    }

    /// Downloads an object without holding it in memory - `GET /{bucket}/{key}`, body
    /// left on the socket.
    ///
    /// [`Self::download_file`] reads the whole object before it returns, so peak memory
    /// is the object's size and a large one takes the process with it. This returns as
    /// soon as the response *head* has arrived, and hands the body over a chunk at a
    /// time, so an HTTP server can forward an object it could never hold.
    ///
    /// The returned [`S3DownloadStream`] carries `Content-Length` and `Content-Type`,
    /// which is what forwarding it needs, and holds the connection until it is read to
    /// the end or dropped.
    ///
    /// A failure is still reported as a typed error: a non-2xx answer's body is small -
    /// it is the `<Error><Code>` - so it *is* read, and only a successful one is left
    /// streaming.
    ///
    /// ```no_run
    /// # async fn doc(s3: &my_s3::S3Client) -> Result<(), my_s3::S3Error> {
    /// use tokio::io::AsyncWriteExt;
    ///
    /// let mut stream = s3.download_file_as_stream("my-bucket", "video.mp4").await?;
    /// let mut file = tokio::fs::File::create("video.mp4").await.unwrap();
    ///
    /// while let Some(chunk) = stream.get_next_chunk().await? {
    ///     file.write_all(&chunk).await.unwrap();
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn download_file_as_stream(
        &self,
        bucket_name: &str,
        key: &str,
    ) -> Result<S3DownloadStream, S3Error> {
        let fl_url = flurl::FlUrl::new(self.endpoint.as_str())
            .append_path_segment(bucket_name)
            .append_path_segment(key)
            .with_retries(3);

        let fl_url = super::utils::sign_request(self, fl_url, "GET", [].as_slice())?;

        let response = self.send_get(fl_url).await?;

        let status_code = response.get_status_code();

        if !is_success(status_code) {
            // Small, and the only thing that says *why*. Reading it also settles the
            // connection, which a discarded streaming body would not.
            let body = response.receive_body().await?;
            self.trace_response(status_code, Some(&body));
            return Err(detect_error(status_code, &body));
        }

        // Deliberately not read: it is the object, and leaving it on the socket is the
        // whole point. `read_success_body` is therefore not the right tool here, and
        // calling it would also materialize the body and make `get_body_as_stream`
        // panic.
        self.trace_response(status_code, None);

        Ok(S3DownloadStream::from_response(response))
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

    async fn expect_success(&self, response: FlUrlResponse) -> Result<(), S3Error> {
        self.read_success_body(response).await?;
        Ok(())
    }

    async fn read_success_body(&self, response: FlUrlResponse) -> Result<Vec<u8>, S3Error> {
        let status_code = response.get_status_code();

        // Read the body either way: on success it is the payload, on failure it carries
        // `<Error><Code>`, which is the only reliable way to tell the failures apart.
        let body = response.receive_body().await?;

        self.trace_response(status_code, Some(&body));

        if is_success(status_code) {
            return Ok(body);
        }

        Err(detect_error(status_code, &body))
    }

    /// Sends a `GET`, tracing the request through `FlUrl` itself when
    /// [`Self::debug_to_console`] is on.
    ///
    /// The trace is printed **before** the `?`, so a request that never got an answer -
    /// a timeout, a refused connection - is still shown. That is the case a trace is
    /// most needed for.
    async fn send_get(&self, fl_url: flurl::FlUrl) -> Result<FlUrlResponse, S3Error> {
        if !self.debug_to_console {
            return Ok(fl_url.get().await?);
        }

        let mut request = String::new();
        let response = fl_url.get_with_debug(&mut request).await;
        println!("{} --> {}", DEBUG_PREFIX, request);

        Ok(response?)
    }

    async fn send_head(&self, fl_url: flurl::FlUrl) -> Result<FlUrlResponse, S3Error> {
        if !self.debug_to_console {
            return Ok(fl_url.head().await?);
        }

        let mut request = String::new();
        let response = fl_url.head_with_debug(&mut request).await;
        println!("{} --> {}", DEBUG_PREFIX, request);

        Ok(response?)
    }

    async fn send_delete(&self, fl_url: flurl::FlUrl) -> Result<FlUrlResponse, S3Error> {
        if !self.debug_to_console {
            return Ok(fl_url.delete().await?);
        }

        let mut request = String::new();
        let response = fl_url.delete_with_debug(&mut request).await;
        println!("{} --> {}", DEBUG_PREFIX, request);

        Ok(response?)
    }

    async fn send_put(
        &self,
        fl_url: flurl::FlUrl,
        body: flurl::body::HttpRequestBody,
    ) -> Result<FlUrlResponse, S3Error> {
        if !self.debug_to_console {
            return Ok(fl_url.put(body).await?);
        }

        // `FlUrl` dumps the body in full here, with no size limit - which is what makes
        // this useful for the `CreateBucket` XML and expensive for a large object. It
        // costs a copy of the payload, and it is opt-in, so that is the debugging price.
        let mut request = String::new();
        let response = fl_url.put_with_debug(body, &mut request).await;
        println!("{} --> {}", DEBUG_PREFIX, request);

        Ok(response?)
    }

    /// The streamed counterpart. `FlUrl` traces the head only here - a streamed payload
    /// exists only as it is written to the socket, so printing it would mean buffering
    /// the very thing streaming avoids.
    async fn send_put_streamed(
        &self,
        fl_url: flurl::FlUrl,
        body: RequestBodyStream<Vec<u8>>,
        content_length: usize,
    ) -> Result<FlUrlResponse, S3Error> {
        if !self.debug_to_console {
            return Ok(fl_url
                .put_request_streamed(body, Some(content_length))
                .await?);
        }

        let mut request = String::new();
        let response = fl_url
            .put_request_streamed_with_debug(body, Some(content_length), &mut request)
            .await;
        println!("{} --> {}", DEBUG_PREFIX, request);

        Ok(response?)
    }

    /// Prints the answer, when [`Self::debug_to_console`] is on.
    ///
    /// `FlUrl` traces requests but not answers, and it cannot: `receive_body` consumes
    /// the body and `get_body_as_stream` hands it over, so tracing it there would mean
    /// buffering an entire downloaded object. Here the body has been read already and
    /// the outcome is known, which is what makes the size/content asymmetry possible.
    ///
    /// `body` is `None` when the outcome was decided without reading it - a `416`, or a
    /// server that ignored `Range` and is about to send a whole object nobody asked
    /// for. Printing a zero length there would be a lie.
    fn trace_response(&self, status_code: u16, body: Option<&[u8]>) {
        if !self.debug_to_console {
            return;
        }

        println!("{}", format_response_trace(status_code, body));
    }
}

/// A failure is printed in full: that body is the `<Error><Code>` saying why, and it is
/// small. A success is printed as a size - it is the object that was just downloaded.
fn format_response_trace(status_code: u16, body: Option<&[u8]>) -> String {
    let Some(body) = body else {
        return format!("{} <-- {}, body not read", DEBUG_PREFIX, status_code);
    };

    if is_success(status_code) {
        return format!(
            "{} <-- {}, body {} bytes",
            DEBUG_PREFIX,
            status_code,
            body.len()
        );
    }

    format!(
        "{} <-- {}, body {} bytes: {}",
        DEBUG_PREFIX,
        status_code,
        body.len(),
        String::from_utf8_lossy(body)
    )
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

/// Reads the region out of a `GetBucketLocation` answer.
///
/// The document is a bare `<LocationConstraint>` at the root, and `us-east-1` is stated
/// by leaving it **empty** - the same "the default region is the absent one" rule that
/// [`create_bucket_configuration`] obeys from the other side.
///
/// Empty comes in two spellings, and only one of them survives the reader:
/// `<LocationConstraint></LocationConstraint>` reads as `Some("")`, while AWS's actual
/// `<LocationConstraint/>` has no text node at all and reads as `None` - which is also
/// what a proxy's HTML error page reads as. Telling those two apart takes looking for
/// the element itself, and the difference matters: one is an answer, the other must not
/// be reported as a region.
fn parse_bucket_location(body: &[u8]) -> Result<S3Region, S3Error> {
    match crate::xml::read_node_text(body, "LocationConstraint") {
        Some(region) if region.is_empty() => Ok(S3Region::AwsUsEast1),
        Some(region) => Ok(S3Region::from_str(region.as_str())),
        None if contains(body, b"<LocationConstraint") => Ok(S3Region::AwsUsEast1),
        None => Err(S3Error::Other(format!(
            "GetBucketLocation answered with a body that is not a LocationConstraint: {}",
            String::from_utf8_lossy(body)
        ))),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
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

    /// The ordinary answer.
    #[test]
    fn a_regional_bucket_reports_its_region() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">eu-west-1</LocationConstraint>"#;

        assert_eq!(
            parse_bucket_location(xml.as_bytes()).unwrap(),
            S3Region::AwsEuWest1
        );
    }

    /// A region outside the catalogue has to survive the round trip - the answer is the
    /// storage's, not ours to validate.
    #[test]
    fn an_unknown_region_survives_the_round_trip() {
        let xml = "<LocationConstraint>some-private-ceph</LocationConstraint>";

        assert_eq!(
            parse_bucket_location(xml.as_bytes()).unwrap(),
            S3Region::Other("some-private-ceph".to_string())
        );
    }

    /// Both spellings of "empty" mean `us-east-1`, and only one of them has a text node
    /// for the reader to find - AWS sends the self-closing one.
    #[test]
    fn an_empty_constraint_is_us_east_1_in_either_spelling() {
        for xml in [
            r#"<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>"#,
            r#"<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>"#,
            "<LocationConstraint/>",
        ] {
            assert_eq!(
                parse_bucket_location(xml.as_bytes()).unwrap(),
                S3Region::AwsUsEast1,
                "got it wrong for {}",
                xml
            );
        }
    }

    /// The reason the self-closing case cannot simply be "no text means us-east-1": a
    /// proxy's error page reads exactly the same way, and reporting it as a region
    /// would be inventing an answer.
    #[test]
    fn a_body_that_is_not_a_location_is_an_error_not_a_default() {
        for body in [
            b"502 Bad Gateway".as_slice(),
            b"".as_slice(),
            b"<html>nope</html>".as_slice(),
            b"<Error><Code>AccessDenied</Code></Error>".as_slice(),
        ] {
            assert!(
                parse_bucket_location(body).is_err(),
                "{:?} must not read as a region",
                String::from_utf8_lossy(body)
            );
        }
    }

    /// The asymmetry the whole trace exists for: a failure is the `<Error><Code>` that
    /// explains itself, a success is an object nobody wants on the console.
    #[test]
    fn a_failed_answer_is_traced_in_full_a_successful_one_by_size() {
        let error = "<Error><Code>IllegalLocationConstraintException</Code></Error>";

        assert_eq!(
            format_response_trace(400, Some(error.as_bytes())),
            format!("[my-s3] <-- 400, body {} bytes: {}", error.len(), error)
        );

        assert_eq!(
            format_response_trace(200, Some(&vec![0u8; 1_048_576])),
            "[my-s3] <-- 200, body 1048576 bytes"
        );
    }

    /// A body that was never read must not be reported as an empty one - 416, and the
    /// server that ignored `Range` and started sending the whole object, both end up
    /// here.
    #[test]
    fn an_unread_body_says_so() {
        assert_eq!(
            format_response_trace(416, None),
            "[my-s3] <-- 416, body not read"
        );
    }

    /// 204 has no body and is still a success, so it must not be traced as a failure.
    #[test]
    fn a_204_is_traced_as_the_success_it_is() {
        assert_eq!(
            format_response_trace(204, Some(&[])),
            "[my-s3] <-- 204, body 0 bytes"
        );
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
