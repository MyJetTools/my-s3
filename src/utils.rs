use flurl::FlUrl;
use hmac::{Hmac, KeyInit, Mac};
use rust_extensions::date_time::DateTimeAsMicroseconds;
use sha2::{Digest, Sha256};

use crate::{S3Client, S3Error};

pub type HmacSha256 = Hmac<Sha256>;

pub fn populate_headers(
    s3: &S3Client,
    fl_url: FlUrl,
    method: &str,
    bucket_name: &str,
    key: Option<&str>,
    content: &[u8],
) -> Result<FlUrl, S3Error> {
    let service = "s3";
    let payload_hash = hex::encode(sha2::Sha256::digest(content));

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
    let hashed_canonical_request = hex::encode(sha2::Sha256::digest(canonical_request.as_bytes()));

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

    let signature = hex::encode(bytes);

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer test from the AWS docs ("Examples of how to derive a signing key
    /// for Signature Version 4"). This pins the whole HMAC chain, so a future bump of
    /// `hmac`/`sha2` that changes the output bytes fails here instead of turning every
    /// request into a 403.
    #[test]
    fn signature_key_matches_aws_reference_vector() {
        let key = get_signature_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
            "iam",
        );

        assert_eq!(
            hex::encode(key),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }

    /// The payload hash is hex-encoded by hand at every call site; a byte < 0x10 must
    /// stay zero-padded to two digits. `sha2::Sha256::digest(b"")` is the canonical
    /// empty-payload hash SigV4 uses for bodyless requests.
    #[test]
    fn empty_payload_hash_is_the_canonical_sha256() {
        assert_eq!(
            hex::encode(sha2::Sha256::digest([].as_slice())),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn amz_timestamp_is_compact_iso8601_utc() {
        let timestamp = get_amz_timestamp();

        // AWS requires exactly YYYYMMDDTHHMMSSZ - 16 chars, no separators, no fraction.
        assert_eq!(timestamp.len(), 16, "got {:?}", timestamp);
        assert!(timestamp.ends_with('Z'), "got {:?}", timestamp);
        assert_eq!(timestamp.as_bytes()[8], b'T', "got {:?}", timestamp);
        assert!(
            timestamp[..8].bytes().all(|b| b.is_ascii_digit())
                && timestamp[9..15].bytes().all(|b| b.is_ascii_digit()),
            "got {:?}",
            timestamp
        );
    }
}
