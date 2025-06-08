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

        let mut response = fl_url.get().await?;

        let status_code = response.get_status_code();
        if status_code == 200 {
            let body = response.receive_body().await?;
            return Ok(body);
        }

        let body = response.body_as_str().await?;

        let err = format!("Status Code: {}. Err: {}", status_code, body);

        Err(err.into())
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

        let mut response = fl_url.get().await?;

        let status_code = response.get_status_code();
        if status_code == 200 {
            let body = response.receive_body().await?;
            return Ok(body);
        }

        let err = response.body_as_str().await?;
        let err = format!("Status Code: {}. Err: {}", status_code, err);

        Err(err.into())
    }

    pub async fn create_bucket(&self, bucket_name: &str) -> Result<(), S3Error> {
        let fl_url = flurl::FlUrl::new(self.endpoint.as_str())
            .append_path_segment(bucket_name)
            .with_retries(3);

        let fl_url =
            super::utils::populate_headers(self, fl_url, "PUT", bucket_name, None, [].as_slice())?;

        let mut response = fl_url.put(None).await?;

        let status_code = response.get_status_code();
        if status_code == 200 {
            return Ok(());
        }

        let body = response.body_as_str().await?;

        let err = format!("Status Code: {}. Err: {}", status_code, body);

        Err(err.into())
    }
}
