//! End-to-end tests against an in-process S3-compatible server (`fake_s3`).
//!
//! These cover the things that are only observable on the wire and that unit tests
//! cannot reach: whether the signature verifies against the request as sent, what the
//! request target looks like, how the body is framed, and how status codes map onto
//! typed errors.

mod fake_s3;

use std::time::Duration;

use fake_s3::FakeS3;
use sha2::Digest;

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
// CreateBucket: the location constraint
// ---------------------------------------------------------------------------

fn location_constraint_xml(region: &str) -> String {
    format!(
        "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>{}</LocationConstraint></CreateBucketConfiguration>",
        region
    )
}

/// `CreateBucket` names its region twice - the endpoint and the body - and S3 requires
/// the two to agree. An empty body is not "any region", it is literally `us-east-1`, so
/// against every other regional endpoint it used to answer
/// `400 IllegalLocationConstraintException` and no bucket was ever created outside
/// `us-east-1`.
#[tokio::test]
async fn create_bucket_outside_us_east_1_states_the_location() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-west-1");

    client.create_bucket("my-bucket").await.unwrap();

    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].method, "PUT");
    assert_eq!(captured[0].target, "/my-bucket");
    assert_eq!(
        String::from_utf8_lossy(&captured[0].body),
        location_constraint_xml("eu-west-1")
    );
}

/// The body is covered by the signature, so the bytes handed to the signer have to be
/// the bytes that go out. Signing an empty payload and then sending the XML turns the
/// 400 into a 403 SignatureDoesNotMatch - a different bug wearing the same shirt.
#[tokio::test]
async fn the_location_constraint_is_covered_by_the_signature() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-central-1");

    client.create_bucket("my-bucket").await.unwrap();

    let captured = server.captured();

    // `signature_valid` already refuses a payload hash that does not match the body;
    // this pins the header itself, so a regression cannot hide behind the verifier.
    assert_eq!(
        captured[0].header("x-amz-content-sha256"),
        Some(hex::encode(sha2::Sha256::digest(&captured[0].body)).as_str())
    );
    assert!(
        captured[0].signature_valid,
        "the signature must cover the body as sent: {:?}",
        captured[0]
    );
}

/// The one region that must **not** be named: AWS rejects an explicit
/// `LocationConstraint` of `us-east-1`, so there the empty body is the correct request
/// and the payload hash stays the canonical hash of nothing.
#[tokio::test]
async fn create_bucket_in_us_east_1_sends_no_body() {
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    let server = FakeS3::start().await;
    let client = server.client_in_region("us-east-1");

    client.create_bucket("my-bucket").await.unwrap();

    let captured = server.captured();
    assert!(
        captured[0].body.is_empty(),
        "AWS rejects an explicit us-east-1 LocationConstraint, got {:?}",
        String::from_utf8_lossy(&captured[0].body)
    );
    assert_eq!(
        captured[0].header("x-amz-content-sha256"),
        Some(EMPTY_SHA256)
    );
    assert!(captured[0].signature_valid);
}

/// Only `create_bucket` carries a body: adding one to a verb that never had one would
/// break every other call's signature, and this is the assertion that would catch it.
#[tokio::test]
async fn no_other_request_grew_a_body() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-west-1");

    server.push_reply(200, "contents");
    client.download_file("my-bucket", "a.bin").await.unwrap();

    server.push_reply(204, "");
    client.delete_file("my-bucket", "a.bin").await.unwrap();

    for captured in server.captured() {
        assert!(
            captured.body.is_empty(),
            "{} must not carry a body: {:?}",
            captured.method,
            captured
        );
        assert!(captured.signature_valid);
    }
}

// ---------------------------------------------------------------------------
// GetBucketLocation
// ---------------------------------------------------------------------------

fn location_answer(region: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{}</LocationConstraint>",
        region
    )
}

/// `?location` is a valueless flag and it is part of the canonical request, so it has
/// to be appended *before* signing - SigV4 canonicalises it to `location=`. Getting
/// that wrong is a 403 that looks like bad credentials.
#[tokio::test]
async fn get_bucket_location_asks_for_the_location_subresource() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-west-1");

    server.push_reply(200, location_answer("eu-west-1").as_str());

    let region = client.get_bucket_location("my-bucket").await.unwrap();

    assert_eq!(region, my_s3::S3Region::AwsEuWest1);

    let captured = server.captured();
    assert_eq!(captured[0].method, "GET");
    assert_eq!(captured[0].target, "/my-bucket?location");
    assert!(
        captured[0].signature_valid,
        "the query param must be covered by the signature: {:?}",
        captured[0]
    );
}

/// The answer is the storage's own, and it does not have to agree with what this client
/// was configured for - that disagreement is the whole reason to ask.
#[tokio::test]
async fn get_bucket_location_reports_a_region_other_than_the_configured_one() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-west-1");

    server.push_reply(200, location_answer("fsn1").as_str());

    assert_eq!(
        client.get_bucket_location("my-bucket").await.unwrap(),
        my_s3::S3Region::HetznerFsn1
    );
}

/// AWS states `us-east-1` by sending an empty constraint - the same asymmetry
/// `CreateBucket` has from the other side.
#[tokio::test]
async fn get_bucket_location_reads_an_empty_constraint_as_us_east_1() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("us-east-1");

    server.push_reply(
        200,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>",
    );

    assert_eq!(
        client.get_bucket_location("my-bucket").await.unwrap(),
        my_s3::S3Region::AwsUsEast1
    );
}

#[tokio::test]
async fn get_bucket_location_on_a_missing_bucket_is_typed() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        404,
        "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist.</Message></Error>",
    );

    let err = client.get_bucket_location("my-bucket").await.unwrap_err();

    assert!(err.is_bucket_not_found());
}

// ---------------------------------------------------------------------------
// CheckIfBucketExists
// ---------------------------------------------------------------------------

/// A HEAD carries no body, in the request or in the answer, so the status code is the
/// entire result.
#[tokio::test]
async fn a_bucket_that_is_there_is_reported_as_existing() {
    let server = FakeS3::start().await;
    let client = server.client();

    assert!(client.check_if_bucket_exists("my-bucket").await.unwrap());

    let captured = server.captured();
    assert_eq!(captured[0].method, "HEAD");
    assert_eq!(captured[0].target, "/my-bucket");
    assert!(captured[0].body.is_empty());
    assert!(captured[0].signature_valid);
}

/// "Not there" is an answer, not a failure: `Ok(false)`, so the caller does not have to
/// pattern-match an error to learn something ordinary.
#[tokio::test]
async fn a_missing_bucket_is_reported_as_absent_not_as_an_error() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(404, "");

    assert!(!client.check_if_bucket_exists("my-bucket").await.unwrap());
}

/// A 403 must not collapse into "it exists": it means the name belongs to another
/// account *or* that these credentials are wrong, and the second one has to be visible.
#[tokio::test]
async fn a_forbidden_bucket_stays_an_error() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(403, "");

    let err = client
        .check_if_bucket_exists("my-bucket")
        .await
        .unwrap_err();

    assert_eq!(err.get_status_code(), Some(403));
    assert!(!err.is_retryable());
}

/// A HEAD followed by an ordinary request on the same client, end to end - the sequence
/// a caller makes when it checks for the bucket and then uses it.
///
/// Note this does not prove anything about connection pooling: the client survives a
/// server that wrongly writes a body after HEAD headers too, so the assertion here is
/// only that both calls complete and both are seen.
#[tokio::test]
async fn a_head_is_followed_by_a_working_request() {
    let server = FakeS3::start().await;
    let client = server.client();

    assert!(client.check_if_bucket_exists("my-bucket").await.unwrap());

    server.push_reply(200, "file contents");
    let body = client.download_file("my-bucket", "a.bin").await.unwrap();

    assert_eq!(body, b"file contents");
    assert_eq!(server.request_count(), 2);
}

// ---------------------------------------------------------------------------
// Debug mode
// ---------------------------------------------------------------------------

/// Tracing must be a pure observation: the same bytes go out, and the signature still
/// verifies. Routing a request through `FlUrl`'s `*_with_debug` variants is the kind of
/// change that could quietly compile the request differently.
#[tokio::test]
async fn debug_mode_does_not_change_what_goes_on_the_wire() {
    let server = FakeS3::start().await;

    let quiet = server.client_in_region("eu-west-1");
    quiet.create_bucket("my-bucket").await.unwrap();

    let loud = server.client_in_region("eu-west-1").debug_to_console();
    loud.create_bucket("my-bucket").await.unwrap();

    let captured = server.captured();
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0].body, captured[1].body);
    assert_eq!(captured[0].target, captured[1].target);
    assert!(
        captured[1].signature_valid,
        "debug mode must not disturb the signature: {:?}",
        captured[1]
    );
}

/// Every verb has its own `FlUrl` debug entry point, including the streamed one, so
/// each path is exercised - a missing one would show up as a compile error at best and
/// a silently untraced request at worst.
#[tokio::test]
async fn every_verb_survives_debug_mode() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-west-1").debug_to_console();

    client.create_bucket("my-bucket").await.unwrap();

    client
        .upload("my-bucket", "a.bin", b"hello".to_vec(), UPLOAD_TIMEOUT)
        .await
        .unwrap();

    client
        .upload_streamed(
            "my-bucket",
            "b.bin",
            body_from(b"streamed".to_vec(), 4),
            8,
            UPLOAD_TIMEOUT,
        )
        .await
        .unwrap();

    server.push_reply(200, "contents");
    client.download_file("my-bucket", "a.bin").await.unwrap();

    server.push_reply(204, "");
    client.delete_file("my-bucket", "a.bin").await.unwrap();

    client.check_if_bucket_exists("my-bucket").await.unwrap();

    server.push_reply(200, location_answer("eu-west-1").as_str());
    client.get_bucket_location("my-bucket").await.unwrap();

    assert_eq!(server.request_count(), 7);
    for captured in server.captured() {
        assert!(
            captured.signature_valid,
            "{} {} lost its signature under debug mode",
            captured.method, captured.target
        );
    }
}

/// The failure path is the one debug mode is turned on for, so it has to survive it -
/// and still come back typed rather than as a printed message.
#[tokio::test]
async fn a_failure_under_debug_mode_is_still_typed() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-west-1").debug_to_console();

    server.push_reply(
        400,
        "<Error><Code>IllegalLocationConstraintException</Code><Message>The unspecified location constraint is incompatible for the region specific endpoint this request was sent to.</Message></Error>",
    );

    let err = client.create_bucket("my-bucket").await.unwrap_err();

    assert_eq!(err.get_status_code(), Some(400));
    assert!(!err.is_retryable());
}

// ---------------------------------------------------------------------------
// CreateBucket: creating one that is already there
// ---------------------------------------------------------------------------

/// Creating the bucket before using it is the normal way to ensure it exists, so the
/// call has to survive being made again against a bucket that is already ours - S3
/// answers that with 409 `BucketAlreadyOwnedByYou`.
#[tokio::test]
async fn creating_a_bucket_that_is_already_ours_is_tolerated() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-west-1");

    // First call: the bucket gets created.
    client
        .create_bucket_if_not_exists("my-bucket")
        .await
        .unwrap();

    // Every call after that: S3 says it is already there and it is ours.
    server.push_reply(
        409,
        "<Error><Code>BucketAlreadyOwnedByYou</Code><Message>you own it</Message></Error>",
    );

    client
        .create_bucket_if_not_exists("my-bucket")
        .await
        .unwrap();

    let captured = server.captured();
    assert_eq!(captured.len(), 2);

    // The repeat is the same well-formed, correctly signed request as the first one -
    // it is answered differently, not sent differently.
    for attempt in &captured {
        assert_eq!(
            String::from_utf8_lossy(&attempt.body),
            location_constraint_xml("eu-west-1")
        );
        assert!(attempt.signature_valid);
    }
}

/// The tolerance stops exactly where the bucket stops being ours: a name held by
/// another account means the bucket that exists is not the one about to be written to.
#[tokio::test]
async fn a_bucket_owned_by_somebody_else_is_not_tolerated() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-west-1");

    server.push_reply(
        409,
        "<Error><Code>BucketAlreadyExists</Code><Message>taken</Message></Error>",
    );

    let err = client
        .create_bucket_if_not_exists("my-bucket")
        .await
        .unwrap_err();

    assert!(err.is_bucket_already_exists());
    assert!(!err.is_bucket_already_owned_by_you());
}

/// A real failure is not swallowed either - only the "already ours" answer is.
#[tokio::test]
async fn create_bucket_if_not_exists_still_reports_a_real_failure() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-west-1");

    server.push_reply(
        403,
        "<Error><Code>AccessDenied</Code><Message>no</Message></Error>",
    );

    let err = client
        .create_bucket_if_not_exists("my-bucket")
        .await
        .unwrap_err();

    assert_eq!(err.get_status_code(), Some(403));
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
