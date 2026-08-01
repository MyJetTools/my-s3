//! End-to-end tests against an in-process S3-compatible server (`fake_s3`).
//!
//! These cover the things that are only observable on the wire and that unit tests
//! cannot reach: whether the signature verifies against the request as sent, what the
//! request target looks like, how the body is framed, and how status codes map onto
//! typed errors.

mod fake_s3;

use std::time::Duration;

use fake_s3::FakeS3;

const UPLOAD_TIMEOUT: Duration = Duration::from_secs(30);

fn no_such_key_xml() -> &'static str {
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>"
}

/// Pushes `content` through a channel the way a caller is expected to, and hands back
/// the receiver.
fn body_from(content: Vec<u8>, chunk_size: usize) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = tokio::sync::mpsc::channel(4);

    tokio::spawn(async move {
        for chunk in content.chunks(chunk_size) {
            if sender.send(chunk.to_vec()).await.is_err() {
                break;
            }
        }
        // Dropping the sender terminates the body.
    });

    receiver
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// The signature has to verify against the request *as received*. This is what catches
/// signing a URL that was built differently from the one sent - the failure mode there
/// is a 403 that looks like bad credentials.
#[tokio::test]
async fn buffered_upload_is_signed_correctly() {
    let server = FakeS3::start().await;
    let client = server.client();

    client
        .upload(
            "my-bucket",
            "hello.txt",
            b"hello world".to_vec(),
            UPLOAD_TIMEOUT,
        )
        .await
        .unwrap();

    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].method, "PUT");
    assert_eq!(captured[0].target, "/my-bucket/hello.txt");
    assert_eq!(captured[0].body, b"hello world");
    assert!(
        captured[0].signature_valid,
        "signature did not verify: {:?}",
        captured[0]
    );
}

/// An `http://` endpoint used to break signing: the host was derived by stripping only
/// `https://`, so the signed host kept the scheme while the `Host` header did not.
/// Every test here runs over `http://`, so this asserts the specific consequence.
#[tokio::test]
async fn host_is_signed_as_sent_for_a_plain_http_endpoint() {
    let server = FakeS3::start().await;
    let client = server.client();

    client
        .download_file("my-bucket", "hello.txt")
        .await
        .unwrap();

    let captured = server.captured();
    assert!(captured[0].signature_valid);

    // The signed host must be the Host header, port included.
    let host = captured[0].header("host").unwrap();
    assert!(host.starts_with("127.0.0.1:"), "got {:?}", host);
    assert!(!host.contains("http"), "got {:?}", host);
}

/// Keys with slashes must go out as a path so objects appear as folders in the bucket -
/// percent-encoding the separator would create one object literally named `a%2Fb`.
#[tokio::test]
async fn a_key_with_slashes_stays_a_path() {
    let server = FakeS3::start().await;
    let client = server.client();

    client
        .upload(
            "my-bucket",
            "archives/2024/06/backup.tar",
            b"x".to_vec(),
            UPLOAD_TIMEOUT,
        )
        .await
        .unwrap();

    let captured = server.captured();
    assert_eq!(captured[0].target, "/my-bucket/archives/2024/06/backup.tar");
    assert!(captured[0].signature_valid);
}

/// A key containing a space is percent-encoded on the wire, so the signature has to be
/// computed over the encoded form. Signing the raw key produced a 403.
#[tokio::test]
async fn a_key_needing_percent_encoding_is_signed_in_its_encoded_form() {
    let server = FakeS3::start().await;
    let client = server.client();

    client
        .upload(
            "my-bucket",
            "my folder/a file.txt",
            b"x".to_vec(),
            UPLOAD_TIMEOUT,
        )
        .await
        .unwrap();

    let captured = server.captured();
    assert_eq!(captured[0].target, "/my-bucket/my%20folder/a%20file.txt");
    assert!(
        captured[0].signature_valid,
        "signature must cover the encoded path"
    );
}

// ---------------------------------------------------------------------------
// Streamed upload
// ---------------------------------------------------------------------------

/// The whole point: the body arrives complete, framed by Content-Length rather than
/// chunked, because a SigV4 request is not accepted chunked.
#[tokio::test]
async fn streamed_upload_sends_content_length_and_the_whole_body() {
    let server = FakeS3::start().await;
    let client = server.client();

    // Several chunks, and a size that is not a multiple of the chunk size.
    let content: Vec<u8> = (0..200_000u32).map(|index| (index % 251) as u8).collect();

    client
        .upload_streamed(
            "my-bucket",
            "archives/big.bin",
            body_from(content.clone(), 64 * 1024),
            content.len(),
            UPLOAD_TIMEOUT,
        )
        .await
        .unwrap();

    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].method, "PUT");
    assert_eq!(captured[0].target, "/my-bucket/archives/big.bin");

    assert_eq!(
        captured[0].header("content-length"),
        Some(content.len().to_string().as_str())
    );
    assert!(
        !captured[0].has_header("transfer-encoding"),
        "a SigV4 request must not go out chunked"
    );

    assert_eq!(captured[0].body.len(), content.len());
    assert_eq!(captured[0].body, content);
}

/// The streamed path cannot hash a payload it has not produced yet, so it declares
/// `UNSIGNED-PAYLOAD`. Asserted explicitly because it is a real (if accepted) reduction
/// in what the signature covers.
#[tokio::test]
async fn streamed_upload_declares_an_unsigned_payload_and_still_signs_the_rest() {
    let server = FakeS3::start().await;
    let client = server.client();

    client
        .upload_streamed(
            "my-bucket",
            "a.bin",
            body_from(b"payload".to_vec(), 4),
            7,
            UPLOAD_TIMEOUT,
        )
        .await
        .unwrap();

    let captured = server.captured();
    assert_eq!(
        captured[0].header("x-amz-content-sha256"),
        Some("UNSIGNED-PAYLOAD")
    );
    // Headers, verb and path are still covered.
    assert!(captured[0].signature_valid);
}

#[tokio::test]
async fn streamed_upload_maps_a_failure_to_a_typed_error() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        403,
        "<Error><Code>AccessDenied</Code><Message>no</Message></Error>",
    );

    let err = client
        .upload_streamed(
            "my-bucket",
            "a.bin",
            body_from(b"payload".to_vec(), 4),
            7,
            UPLOAD_TIMEOUT,
        )
        .await
        .unwrap_err();

    assert_eq!(err.get_status_code(), Some(403));
    assert!(!err.is_retryable(), "403 must not be retried");
}

// ---------------------------------------------------------------------------
// Retries around the streamed upload
// ---------------------------------------------------------------------------

/// A streamed body is attempted exactly once by FlUrl, so the retry has to re-run the
/// whole thing - including re-reading the payload from the beginning.
#[tokio::test]
async fn retries_resend_the_whole_payload_after_a_retryable_failure() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        503,
        "<Error><Code>ServiceUnavailable</Code><Message>later</Message></Error>",
    );

    let content = vec![7u8; 100_000];

    client
        .upload_streamed_with_retries(
            "my-bucket",
            "a.bin",
            content.len(),
            UPLOAD_TIMEOUT,
            3,
            || body_from(vec![7u8; 100_000], 16 * 1024),
        )
        .await
        .unwrap();

    let captured = server.captured();
    assert_eq!(captured.len(), 2, "expected one failure and one success");

    // Both attempts must carry the complete payload - a resumed reader would send the
    // second attempt short.
    for attempt in &captured {
        assert_eq!(attempt.body.len(), content.len());
        assert_eq!(attempt.body, content);
    }
}

/// A deterministic failure must not be retried at all: repeating it only burns the
/// payload again.
#[tokio::test]
async fn a_non_retryable_failure_is_attempted_once() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        403,
        "<Error><Code>AccessDenied</Code><Message>no</Message></Error>",
    );

    let err = client
        .upload_streamed_with_retries("my-bucket", "a.bin", 8, UPLOAD_TIMEOUT, 5, || {
            body_from(b"contents".to_vec(), 4)
        })
        .await
        .unwrap_err();

    assert_eq!(err.get_status_code(), Some(403));
    assert_eq!(server.request_count(), 1, "403 must not be retried");
}

#[tokio::test]
async fn retries_give_up_and_return_the_last_error() {
    let server = FakeS3::start().await;
    let client = server.client();

    for _ in 0..4 {
        server.push_reply(
            503,
            "<Error><Code>ServiceUnavailable</Code><Message>later</Message></Error>",
        );
    }

    let err = client
        .upload_streamed_with_retries("my-bucket", "a.bin", 8, UPLOAD_TIMEOUT, 2, || {
            body_from(b"contents".to_vec(), 4)
        })
        .await
        .unwrap_err();

    assert_eq!(err.get_status_code(), Some(503));
    assert!(err.is_retryable());
    // 1 initial attempt + 2 retries
    assert_eq!(server.request_count(), 3);
}

// ---------------------------------------------------------------------------
// Delete: the 204 bug
// ---------------------------------------------------------------------------

/// S3 answers a successful DeleteObject with 204 No Content. Accepting only 200 made
/// every delete return an error, and a hard delete silently removed nothing.
#[tokio::test]
async fn delete_succeeds_on_204_no_content() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(204, "");

    client.delete_file("my-bucket", "a/b.bin").await.unwrap();

    let captured = server.captured();
    assert_eq!(captured[0].method, "DELETE");
    assert_eq!(captured[0].target, "/my-bucket/a/b.bin");
    assert!(captured[0].signature_valid);
}

#[tokio::test]
async fn delete_reports_a_real_failure() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        403,
        "<Error><Code>AccessDenied</Code><Message>no</Message></Error>",
    );

    let err = client.delete_file("my-bucket", "a.bin").await.unwrap_err();

    assert_eq!(err.get_status_code(), Some(403));
}

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_missing_key_is_typed_not_a_string() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(404, no_such_key_xml());

    let err = client
        .download_file("my-bucket", "gone.bin")
        .await
        .unwrap_err();

    assert!(err.is_key_not_found());
    assert!(!err.is_retryable());
}

/// Re-creating a bucket we already own is the state on every restart, and it arrives as
/// 409 - the same status as `BucketAlreadyExists`, so only the body distinguishes them.
#[tokio::test]
async fn recreating_our_own_bucket_is_typed() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        409,
        "<Error><Code>BucketAlreadyOwnedByYou</Code><Message>you own it</Message></Error>",
    );

    let err = client.create_bucket("my-bucket").await.unwrap_err();

    assert!(err.is_bucket_already_owned_by_you());
    assert!(err.bucket_name_is_taken());
    assert!(!err.is_bucket_already_exists());

    let captured = server.captured();
    assert_eq!(captured[0].target, "/my-bucket");
    assert!(captured[0].signature_valid);
}

#[tokio::test]
async fn a_bucket_taken_by_somebody_else_stays_distinct() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        409,
        "<Error><Code>BucketAlreadyExists</Code><Message>taken</Message></Error>",
    );

    let err = client.create_bucket("my-bucket").await.unwrap_err();

    assert!(err.is_bucket_already_exists());
    assert!(!err.is_bucket_already_owned_by_you());
    assert!(err.bucket_name_is_taken());
}

#[tokio::test]
async fn create_bucket_succeeds_on_200() {
    let server = FakeS3::start().await;
    let client = server.client();

    client.create_bucket("my-bucket").await.unwrap();

    assert_eq!(server.captured()[0].method, "PUT");
}

// ---------------------------------------------------------------------------
// Download, including ranges
// ---------------------------------------------------------------------------

#[tokio::test]
async fn download_returns_the_body() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, "file contents");

    let body = client.download_file("my-bucket", "a.bin").await.unwrap();

    assert_eq!(body, b"file contents");
    assert_eq!(server.captured()[0].method, "GET");
}

/// `Range` is not in SignedHeaders, so it is added after signing - this checks that
/// doing so does not invalidate the signature.
#[tokio::test]
async fn a_range_request_is_still_correctly_signed() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(206, "artial");

    let body = client
        .download_file_range("my-bucket", "a.bin", 1, Some(6))
        .await
        .unwrap();

    assert_eq!(body, b"artial");

    let captured = server.captured();
    assert_eq!(captured[0].header("range"), Some("bytes=1-6"));
    assert!(captured[0].signature_valid);
}

#[tokio::test]
async fn an_open_ended_range_is_sent_without_an_upper_bound() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(206, "tail");

    client
        .download_file_range("my-bucket", "a.bin", 10, None)
        .await
        .unwrap();

    assert_eq!(server.captured()[0].header("range"), Some("bytes=10-"));
}

#[tokio::test]
async fn a_range_past_the_end_is_typed() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        416,
        "<Error><Code>InvalidRange</Code><Message>nope</Message></Error>",
    );

    let err = client
        .download_file_range("my-bucket", "a.bin", 9_000, None)
        .await
        .unwrap_err();

    assert!(err.is_range_not_satisfiable());
}

/// If the server ignores `Range` and returns the whole object, silently handing back
/// far more data than asked for would be worse than failing.
#[tokio::test]
async fn a_range_answered_with_200_is_reported() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, "the entire object");

    let err = client
        .download_file_range("my-bucket", "a.bin", 1, Some(3))
        .await
        .unwrap_err();

    assert!(!err.is_range_not_satisfiable());
    assert!(err.to_string().contains("ignored the Range header"));
}

#[tokio::test]
async fn an_inverted_range_is_rejected_before_any_request() {
    let server = FakeS3::start().await;
    let client = server.client();

    let err = client
        .download_file_range("my-bucket", "a.bin", 10, Some(5))
        .await
        .unwrap_err();

    assert!(err.to_string().contains("Invalid range"));
    assert_eq!(server.request_count(), 0, "must not hit the network");
}
