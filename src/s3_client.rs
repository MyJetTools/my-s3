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
    ) -> Result<(), String> {
        let fl_url = flurl::FlUrl::new(self.endpoint.as_str())
            .append_path_segment(bucket_name)
            .append_path_segment(key);

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
            response.body_as_str().await.unwrap()
        );

        Err(err)
    }

    pub async fn create_bucket(&self, bucket_name: &str) -> Result<(), String> {
        let fl_url = flurl::FlUrl::new(self.endpoint.as_str()).append_path_segment(bucket_name);

        let fl_url =
            super::utils::populate_headers(self, fl_url, "PUT", bucket_name, None, [].as_slice())?;

        let mut response = fl_url.put(None).await.map_err(|itm| itm.to_string())?;

        let status_code = response.get_status_code();
        if status_code == 200 {
            return Ok(());
        }

        let err = format!(
            "Status Code: {}. Err: {}",
            status_code,
            response.body_as_str().await.unwrap()
        );

        Err(err)
    }
}
