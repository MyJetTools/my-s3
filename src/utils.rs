use flurl::FlUrl;
use hmac::{Hmac, KeyInit, Mac};
use rust_extensions::date_time::DateTimeAsMicroseconds;
use sha2::{Digest, Sha256};

use crate::{S3Client, S3Error};

pub type HmacSha256 = Hmac<Sha256>;

/// Signs an already-built request with SigV4 and attaches the three headers S3 needs.
///
/// The canonical request is derived from `fl_url`'s own url builder rather than from
/// a separately formatted bucket/key pair. That matters: `FlUrl` percent-encodes path
/// segments and query params as it builds the URL, and it sends `Host` as
/// `url_builder.get_host_port()`. Re-deriving those strings by hand meant signing
/// something the wire never carried - a key with a space, a non-ASCII character, or a
/// `http://` endpoint (the old code only stripped `https://`) all produced a 403 that
/// looked like a credentials problem. Reading them back from the builder makes the
/// signed bytes and the sent bytes the same bytes by construction.
///
/// Call this *after* every `append_path_segment` / `append_query_param`, and before
/// any further `with_header` that must not be signed (only `host`,
/// `x-amz-content-sha256` and `x-amz-date` are in `SignedHeaders`, so unsigned extras
/// such as `Range` are fine either way).
pub fn sign_request(
    s3: &S3Client,
    fl_url: FlUrl,
    method: &str,
    payload: &[u8],
) -> Result<FlUrl, S3Error> {
    let payload_hash = hex::encode(Sha256::digest(payload));
    sign_request_with_payload_hash(s3, fl_url, method, &payload_hash)
}

pub fn sign_request_with_payload_hash(
    s3: &S3Client,
    fl_url: FlUrl,
    method: &str,
    payload_hash: &str,
) -> Result<FlUrl, S3Error> {
    let service = "s3";

    // Exactly what FlUrl will put in the Host header and on the request line.
    let host = fl_url.url_builder.get_host_port().to_string();
    let canonical_uri = fl_url.url_builder.get_path().to_string();
    let canonical_query = canonical_query_string(fl_url.url_builder.get_query());

    let timestamp = get_amz_timestamp();
    let date = timestamp[..8].to_string();

    let canonical_request = format!(
        "{}\n{}\n{}\nhost:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n\nhost;x-amz-content-sha256;x-amz-date\n{}",
        method, canonical_uri, canonical_query, host, payload_hash, timestamp, payload_hash
    );
    let hashed_canonical_request = hex::encode(Sha256::digest(canonical_request.as_bytes()));

    let scope = format!("{}/{}/{}/aws4_request", date, s3.region.as_str(), service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        timestamp, scope, hashed_canonical_request
    );

    let signing_key = get_signature_key(&s3.secret_key, &date, s3.region.as_str(), service);

    let mut mac = HmacSha256::new_from_slice(&signing_key).map_err(|itm| itm.to_string())?;
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature={}",
        s3.access_key, scope, signature
    );

    let fl_url = fl_url
        .with_header("X-Amz-Content-Sha256", payload_hash)
        .with_header("X-Amz-Date", &timestamp)
        .with_header("Authorization", &authorization);

    Ok(fl_url)
}

/// Builds the SigV4 canonical query string out of the query FlUrl already encoded.
///
/// The pairs are taken verbatim - re-encoding them here would be the whole bug this
/// function exists to avoid - and only reordered, since SigV4 requires ascending order
/// by encoded name and then by encoded value. A parameter with no value (`?uploads`)
/// canonicalises to `uploads=`, which is also how the server reads it off the wire.
fn canonical_query_string(query: Option<&str>) -> String {
    let Some(query) = query else {
        return String::new();
    };

    if query.is_empty() {
        return String::new();
    }

    let mut pairs: Vec<(&str, &str)> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (name, value),
            None => (pair, ""),
        })
        .collect();

    // Sort on the (name, value) tuple rather than on the joined string: a byte-wise
    // sort of "name=value" ranks `a-b=1` before `a=2` because '-' < '=', which is the
    // opposite of the name-first order AWS specifies.
    pairs.sort_unstable();

    let mut result = String::with_capacity(query.len() + pairs.len());
    for (index, (name, value)) in pairs.iter().enumerate() {
        if index > 0 {
            result.push('&');
        }
        result.push_str(name);
        result.push('=');
        result.push_str(value);
    }

    result
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

    #[test]
    fn no_query_canonicalises_to_empty_string() {
        assert_eq!(canonical_query_string(None), "");
        assert_eq!(canonical_query_string(Some("")), "");
    }

    /// `?uploads` is a valueless flag; SigV4 wants it as `uploads=`.
    #[test]
    fn valueless_param_gets_an_equals_sign() {
        assert_eq!(canonical_query_string(Some("uploads")), "uploads=");
    }

    /// UploadPart sends `?partNumber=N&uploadId=X`; SigV4 wants them name-sorted, and
    /// "partNumber" < "uploadId" so this pair happens to already be in order - the
    /// point of the test is that the values survive untouched.
    #[test]
    fn upload_part_query_is_sorted_by_name() {
        assert_eq!(
            canonical_query_string(Some("uploadId=abc123&partNumber=7")),
            "partNumber=7&uploadId=abc123"
        );
    }

    /// The pairs must be passed through byte-for-byte: whatever FlUrl percent-encoded
    /// is what the server sees, so re-encoding (or decoding) here breaks the signature.
    #[test]
    fn already_encoded_values_are_not_touched() {
        assert_eq!(
            canonical_query_string(Some("uploadId=2%7EabC.d-e_f%2Bg")),
            "uploadId=2%7EabC.d-e_f%2Bg"
        );
    }

    /// Sorting is by name first, then value - not by the joined "name=value" string.
    /// '-' (0x2D) sorts before '=' (0x3D), so a byte-wise sort of the joined strings
    /// would put `a-b` before `a`, which is not the order AWS specifies.
    #[test]
    fn sort_is_by_name_then_value_not_by_joined_pair() {
        assert_eq!(canonical_query_string(Some("a-b=1&a=2")), "a=2&a-b=1");
        assert_eq!(canonical_query_string(Some("k=2&k=1")), "k=1&k=2");
    }
}
