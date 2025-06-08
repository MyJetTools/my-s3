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
            .put(Some(content))
            .await
            .map_err(|itm| itm.to_string())?;

        let status_code = response.get_status_code();
        if status_code == 200 {
            return Ok(());
        }

        let err = format!(
            "Status Code: {}. Err: {}",
            status_code,
            response.body_as_str().await?
        );

        Err(err.into())
    }

    pub async fn download_file(&self, bucket_name: &str, key: &str) -> Result<Vec<u8>, S3Error> {
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

        let fl_url_response = fl_url.get().await?;

        handle_error(fl_url_response).await
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

        let fl_url_response = fl_url.get().await?;

        handle_error(fl_url_response).await
    }

    pub async fn create_bucket(&self, bucket_name: &str) -> Result<(), S3Error> {
        let fl_url = flurl::FlUrl::new(self.endpoint.as_str())
            .append_path_segment(bucket_name)
            .with_retries(3);

        let fl_url =
            super::utils::populate_headers(self, fl_url, "PUT", bucket_name, None, [].as_slice())?;

        let fl_url_response = fl_url.put(None).await?;

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
    let body = fl_url_response.body_as_str().await?;

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

    let node = match xml_reader.find_the_open_node("Error/Code") {
        Ok(result) => result,
        Err(err) => {
            return S3Error::Other(format!(
                "Err: {}. Invalid XML: {:?}",
                err,
                std::str::from_utf8(&body)
            ));
        }
    };

    if node.is_none() {
        return S3Error::Other(format!(" Invalid XML: {:?}", std::str::from_utf8(&body)));
    }

    let open_node = xml_reader.read_next_tag().unwrap().unwrap();

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
