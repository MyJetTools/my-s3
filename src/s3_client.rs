use crate::s3_body_reader::S3BodyReader;

use super::S3Error;

pub struct S3Client {
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
    pub endpoint: String,
}

impl S3Client {
    pub async fn upload_file(
        &self,
        bucket_name: &str,
        key: &str,
        content: Vec<u8>,
    ) -> Result<(), S3Error> {
        let fl_url = flurl::FlUrl::new(self.endpoint.as_str())
            .append_path_segment(bucket_name)
            .append_path_segment(key)
            .with_retries(3);

        let fl_url = super::utils::populate_headers(
            self,
            fl_url,
            "PUT",
            bucket_name,
            Some(key),
            content.as_slice(),
        )?;

        let mut response = fl_url
            .put(flurl::body::HttpRequestBody::from_raw_data(content, None))
            .await?;

        let status_code = response.get_status_code();
        if status_code == 200 {
            return Ok(());
        }

        let err = format!(
            "Status Code: {}. Err: {}",
            status_code,
            response.get_body_as_str().await?
        );

        Err(err.into())
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
        if let Some(end) = end {
            if end < start {
                return Err(S3Error::Other(format!(
                    "Invalid range: end ({}) < start ({})",
                    end, start
                )));
            }
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

        let fl_url = super::utils::populate_headers(
            self,
            fl_url,
            "GET",
            bucket_name,
            Some(key),
            [].as_slice(),
        )?;

        let fl_url = match range {
            Some((start, Some(end))) => fl_url.with_header("Range", format!("bytes={}-{}", start, end)),
            Some((start, None)) => fl_url.with_header("Range", format!("bytes={}-", start)),
            None => fl_url,
        };

        let mut fl_url_response = fl_url.get().await?;

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

        let body = fl_url_response.get_body_as_str().await?;
        Err(format!("Status Code: {}. Err: {}", status_code, body).into())
    }

    pub async fn delete_file(&self, bucket_name: &str, key: &str) -> Result<Vec<u8>, S3Error> {
        let fl_url = flurl::FlUrl::new(self.endpoint.as_str())
            .append_path_segment(bucket_name)
            .append_path_segment(key)
            .with_retries(3);

        let fl_url = super::utils::populate_headers(
            self,
            fl_url,
            "DELETE",
            bucket_name,
            Some(key),
            [].as_slice(),
        )?;

        let fl_url_response = fl_url.delete().await?;

        handle_error(fl_url_response).await
    }

    pub async fn create_bucket(&self, bucket_name: &str) -> Result<(), S3Error> {
        let fl_url = flurl::FlUrl::new(self.endpoint.as_str())
            .append_path_segment(bucket_name)
            .with_retries(3);

        let fl_url =
            super::utils::populate_headers(self, fl_url, "PUT", bucket_name, None, [].as_slice())?;

        let fl_url_response = fl_url.put(flurl::body::HttpRequestBody::empty()).await?;

        handle_error(fl_url_response).await
    }
}

async fn handle_error<TResult: S3BodyReader<Result = TResult>>(
    mut fl_url_response: flurl::FlUrlResponse,
) -> Result<TResult, S3Error> {
    let status_code = fl_url_response.get_status_code();
    if status_code == 200 {
        if TResult::HAS_BODY {
            let body = fl_url_response.receive_body().await?;
            return Ok(TResult::from_vec(body));
        } else {
            return Ok(TResult::default());
        }
    }

    if status_code == 409 {
        let body = fl_url_response.receive_body().await?;
        return Err(detect_error_from_body(body));
    }
    let body = fl_url_response.get_body_as_str().await?;

    let err = format!("Status Code: {}. Err: {}", status_code, body);

    Err(err.into())
}

fn detect_error_from_body(body: Vec<u8>) -> S3Error {
    let xml_reader = my_xml_reader::MyXmlReader::from_slice(&body);

    let Ok(mut xml_reader) = xml_reader else {
        return S3Error::Other(format!(
            "Expect body as XML. But body is: {:?}",
            std::str::from_utf8(&body)
        ));
    };

    let open_node = match xml_reader.find_the_open_node("Error/Code") {
        Ok(Some(node)) => node,
        Ok(None) => {
            return S3Error::Other(format!(" Invalid XML: {:?}", std::str::from_utf8(&body)));
        }
        Err(err) => {
            return S3Error::Other(format!(
                "Err: {}. Invalid XML: {:?}",
                err,
                std::str::from_utf8(&body)
            ));
        }
    };

    // The reader is now positioned right after `<Code>`; the next tag is the
    // matching `</Code>`, so the error code text lives between the two.
    let close_node = xml_reader.read_next_tag().unwrap().unwrap();

    let value = unsafe {
        std::str::from_utf8_unchecked(&body[open_node.end_pos + 1..close_node.start_pos])
    };

    match value {
        "BucketAlreadyExists" => return S3Error::BucketAlreadyExists,
        _ => S3Error::Other(String::from_utf8(body).unwrap()),
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn detect_bucket_exists_error() {
        let xml = "<Error><Code>BucketAlreadyExists</Code><Message>The requested bucket name is not available.</Message><Resource>chat-bot-files-dev</Resource><RequestId>2fd9b10e5df517b3be17b5df4fe3d8c4</RequestId></Error>";

        let s3_error = super::detect_error_from_body(xml.as_bytes().to_vec());

        assert!(s3_error.is_bucket_already_exists());
    }
}
