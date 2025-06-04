use flurl::FlUrl;
use hmac::{Hmac, Mac};
use rust_extensions::date_time::DateTimeAsMicroseconds;
use sha2::{Digest, Sha256};

use crate::S3Client;

pub type HmacSha256 = Hmac<Sha256>;

pub fn populate_headers(
    s3: &S3Client,
    fl_url: FlUrl,
    method: &str,
    bucket_name: &str,
    key: Option<&str>,
    content: &[u8],
) -> Result<FlUrl, String> {
    let service = "s3";
    let payload_hash = format!("{:x}", sha2::Sha256::digest(content));

    // Prepare request details
    let host = s3.endpoint.trim_start_matches("https://");
    let uri = match key {
        Some(key) => {
            format!("/{}/{}", bucket_name, key)
        }
        None => {
            format!("/{}", bucket_name)
        }
    };
    let timestamp = get_amz_timestamp();
    let date = timestamp[..8].to_string();

    // Canonical request
    let canonical_request = format!(
        "{}\n{}\n\nhost:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n\nhost;x-amz-content-sha256;x-amz-date\n{}",
        method, uri, host, payload_hash, timestamp, payload_hash
    );
    let hashed_canonical_request =
        format!("{:x}", sha2::Sha256::digest(canonical_request.as_bytes()));

    // String to sign
    let scope = format!("{}/{}/{}/aws4_request", date, s3.region, service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        timestamp, scope, hashed_canonical_request
    );

    // Signing key and signature
    let signing_key = get_signature_key(&s3.secret_key, &date, &s3.region, service);

    let mut bytes = HmacSha256::new_from_slice(&signing_key).map_err(|itm| itm.to_string())?;

    bytes.update(string_to_sign.as_bytes());

    let bytes = bytes.finalize().into_bytes();

    let signature = format!("{:x}", bytes);

    // Authorization header
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature={}",
        s3.access_key, scope, signature
    );

    let fl_url = fl_url
        .with_header("X-Amz-Content-Sha256", &payload_hash)
        .with_header("X-Amz-Date", &timestamp)
        .with_header("Authorization", &authorization);
    Ok(fl_url)
}

pub fn get_signature_key(secret_key: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_secret = format!("AWS4{}", secret_key).into_bytes();
    let k_date = HmacSha256::new_from_slice(&k_secret)
        .unwrap()
        .chain_update(date)
        .finalize()
        .into_bytes();
    let k_region = HmacSha256::new_from_slice(&k_date)
        .unwrap()
        .chain_update(region)
        .finalize()
        .into_bytes();
    let k_service = HmacSha256::new_from_slice(&k_region)
        .unwrap()
        .chain_update(service)
        .finalize()
        .into_bytes();
    let result = HmacSha256::new_from_slice(&k_service)
        .unwrap()
        .chain_update("aws4_request")
        .finalize();

    let result = result.into_bytes();

    result.to_vec()
}

pub fn get_amz_timestamp() -> String {
    let now = DateTimeAsMicroseconds::now().to_rfc3339();
    let now = now.replace("-", "");
    let mut now = now.replace(":", "");

    while now.len() > 15 {
        now.pop();
    }

    now.push('Z');

    now
}
