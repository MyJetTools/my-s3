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

// ---------------------------------------------------------------------------
// ListObjectsV2
// ---------------------------------------------------------------------------

fn listing_xml() -> &'static str {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>my-bucket</Name>
  <Prefix>photos/</Prefix>
  <Delimiter>/</Delimiter>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>photos/cover.jpg</Key>
    <LastModified>2024-07-01T12:34:56.000Z</LastModified>
    <ETag>&quot;abc&quot;</ETag>
    <Size>1048576</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <CommonPrefixes><Prefix>photos/2024/</Prefix></CommonPrefixes>
</ListBucketResult>"#
}

/// The plainest possible listing: the sub-resource and nothing else.
#[tokio::test]
async fn list_objects_asks_for_list_type_2_and_nothing_more() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, listing_xml());

    client
        .list_objects_v2("my-bucket", my_s3::S3ListObjectsRequest::default())
        .await
        .unwrap();

    let captured = &server.captured()[0];

    assert_eq!(captured.method, "GET");
    // No trailing slash on the bucket: `/my-bucket`, not `/my-bucket/`.
    assert_eq!(captured.target, "/my-bucket?list-type=2");
    assert!(captured.signature_valid);
    assert!(captured.body.is_empty());
}

/// A parameter that was not asked for must not appear at all - `delimiter=` is a
/// different request from no delimiter, and would flatten a listing that wanted folders.
#[tokio::test]
async fn parameters_that_were_not_asked_for_are_not_sent() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, listing_xml());

    client
        .list_objects_v2(
            "my-bucket",
            my_s3::S3ListObjectsRequest {
                delimiter: Some("/"),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let target = &server.captured()[0].target;

    assert_eq!(target, "/my-bucket?list-type=2&delimiter=%2F");
    assert!(!target.contains("prefix"));
    assert!(!target.contains("continuation-token"));
    assert!(!target.contains("max-keys"));
}

/// **The signing case.** A folder prefix carries `/`, and this one also carries a space.
/// `FlUrl`'s own query encoder would send `photos%2F2024+summer%2F`: S3 would read the
/// `+` as a plus rather than a space and answer with an empty listing, and its own
/// canonical query would say `%20` where ours said `+`, so the request would be refused
/// as `SignatureDoesNotMatch` first.
#[tokio::test]
async fn a_prefix_with_a_slash_and_a_space_is_uri_encoded_not_form_encoded() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, listing_xml());

    client
        .list_objects_v2(
            "my-bucket",
            my_s3::S3ListObjectsRequest {
                prefix: Some("photos/2024 summer/"),
                delimiter: Some("/"),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let captured = &server.captured()[0];

    assert_eq!(
        captured.target,
        "/my-bucket?list-type=2&prefix=photos%2F2024%20summer%2F&delimiter=%2F"
    );
    assert!(
        !captured.target.contains('+'),
        "a space must be %20, never +: {}",
        captured.target
    );
    assert!(captured.signature_valid);
}

/// A continuation token is base64, so it carries `+`, `/` and `=` - the three characters
/// that would otherwise end the parameter early or turn into a different token.
#[tokio::test]
async fn a_continuation_token_reaches_the_wire_intact() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, listing_xml());

    client
        .list_objects_v2(
            "my-bucket",
            my_s3::S3ListObjectsRequest {
                continuation_token: Some("1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM="),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let captured = &server.captured()[0];

    assert_eq!(
        captured.target,
        "/my-bucket?list-type=2&continuation-token=1ueGcxLPRx1Tr%2FXYExHnhbYLgveDs2J%2Fwm36Hy4vbOwM%3D"
    );
    assert!(captured.signature_valid);
}

/// A non-ASCII prefix has to be encoded over its UTF-8 bytes, because that is what the
/// server re-encodes when it rebuilds the canonical query.
#[tokio::test]
async fn a_non_ascii_prefix_is_signed_as_its_utf8_bytes() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, listing_xml());

    client
        .list_objects_v2(
            "my-bucket",
            my_s3::S3ListObjectsRequest {
                prefix: Some("документы/"),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let captured = &server.captured()[0];

    assert_eq!(
        captured.target,
        "/my-bucket?list-type=2&prefix=%D0%B4%D0%BE%D0%BA%D1%83%D0%BC%D0%B5%D0%BD%D1%82%D1%8B%2F"
    );
    assert!(captured.signature_valid);
}

#[tokio::test]
async fn max_keys_is_sent_as_a_number() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, listing_xml());

    client
        .list_objects_v2(
            "my-bucket",
            my_s3::S3ListObjectsRequest {
                max_keys: Some(37),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(
        server.captured()[0].target,
        "/my-bucket?list-type=2&max-keys=37"
    );
}

/// End to end: the answer a real storage sends, read into the shape a caller uses.
#[tokio::test]
async fn list_objects_reads_the_page_the_storage_answered_with() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, listing_xml());

    let page = client
        .list_objects_v2(
            "my-bucket",
            my_s3::S3ListObjectsRequest {
                prefix: Some("photos/"),
                delimiter: Some("/"),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(page.common_prefixes, ["photos/2024/"]);
    assert_eq!(page.objects.len(), 1);
    assert_eq!(page.objects[0].key, "photos/cover.jpg");
    assert_eq!(page.objects[0].size, 1_048_576);
    assert_eq!(page.next_continuation_token, None);
}

/// Walking the whole listing is a loop over the token, and the second request has to
/// carry the first one's token *and* repeat the prefix and delimiter unchanged.
#[tokio::test]
async fn a_truncated_listing_is_resumed_with_the_token_it_handed_back() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        200,
        r#"<ListBucketResult>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>page/2=</NextContinuationToken>
  <Contents><Key>photos/a.jpg</Key><LastModified>x</LastModified><Size>1</Size></Contents>
</ListBucketResult>"#,
    );
    server.push_reply(
        200,
        r#"<ListBucketResult>
  <IsTruncated>false</IsTruncated>
  <Contents><Key>photos/b.jpg</Key><LastModified>x</LastModified><Size>2</Size></Contents>
</ListBucketResult>"#,
    );

    let mut keys = Vec::new();
    let mut token = None;

    loop {
        let page = client
            .list_objects_v2(
                "my-bucket",
                my_s3::S3ListObjectsRequest {
                    prefix: Some("photos/"),
                    delimiter: Some("/"),
                    continuation_token: token.as_deref(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        keys.extend(page.objects.into_iter().map(|object| object.key));

        token = page.next_continuation_token;
        if token.is_none() {
            break;
        }
    }

    assert_eq!(keys, ["photos/a.jpg", "photos/b.jpg"]);

    let captured = server.captured();
    assert_eq!(captured.len(), 2);
    assert!(!captured[0].target.contains("continuation-token"));
    assert_eq!(
        captured[1].target,
        "/my-bucket?list-type=2&prefix=photos%2F&delimiter=%2F&continuation-token=page%2F2%3D"
    );
    assert!(captured[1].signature_valid);
}

#[tokio::test]
async fn listing_a_missing_bucket_is_typed() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        404,
        "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist.</Message></Error>",
    );

    let err = client
        .list_objects_v2("my-bucket", my_s3::S3ListObjectsRequest::default())
        .await
        .unwrap_err();

    assert!(err.is_bucket_not_found());
}

/// A 200 whose body is not a listing at all - a proxy's page, say - must not read as an
/// empty bucket. "There is nothing here" and "I could not tell" are different answers.
#[tokio::test]
async fn a_success_that_is_not_a_listing_is_not_an_empty_bucket() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, "<html><body>Service Unavailable</body></html>");

    assert!(
        client
            .list_objects_v2("my-bucket", my_s3::S3ListObjectsRequest::default())
            .await
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// Streamed download
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_streamed_download_delivers_the_whole_object() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, "the whole object, one chunk or several");

    let mut stream = client
        .download_file_as_stream("my-bucket", "a.bin")
        .await
        .unwrap();

    let mut body = Vec::new();
    while let Some(chunk) = stream.get_next_chunk().await.unwrap() {
        body.extend_from_slice(&chunk);
    }

    assert_eq!(body, b"the whole object, one chunk or several");
    assert_eq!(stream.received(), body.len() as u64);

    let captured = &server.captured()[0];
    assert_eq!(captured.method, "GET");
    assert_eq!(captured.target, "/my-bucket/a.bin");
    assert!(captured.signature_valid);
}

/// Both are what forwarding the object over HTTP needs, and both have to be read off the
/// response before the body is taken - the response is consumed by that.
#[tokio::test]
async fn a_streamed_download_carries_the_length_and_the_type() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, "0123456789");

    let stream = client
        .download_file_as_stream("my-bucket", "a.bin")
        .await
        .unwrap();

    assert_eq!(stream.content_length, Some(10));
    assert_eq!(stream.content_type.as_deref(), Some("application/xml"));
}

/// A failure is still typed: the body of a non-2xx answer is the `<Error><Code>`, it is
/// small, and it is read rather than streamed.
#[tokio::test]
async fn a_streamed_download_of_a_missing_key_is_typed() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(404, no_such_key_xml());

    let err = client
        .download_file_as_stream("my-bucket", "missing.bin")
        .await
        .unwrap_err();

    assert!(err.is_key_not_found());
}

/// **The one that matters for a file that gets written out.** The storage announced 64
/// bytes, sent 9, and hung up. Reporting the end of the stream here would hand back a
/// truncated file and call it a success.
#[tokio::test]
async fn a_body_that_ends_early_is_an_error_not_a_short_file() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_truncated_reply("truncated", 64);

    let mut stream = client
        .download_file_as_stream("my-bucket", "a.bin")
        .await
        .unwrap();

    assert_eq!(stream.content_length, Some(64));

    let mut received = Vec::new();
    let outcome = loop {
        match stream.get_next_chunk().await {
            Ok(Some(chunk)) => received.extend_from_slice(&chunk),
            Ok(None) => break Ok(()),
            Err(err) => break Err(err),
        }
    };

    // Which of the two guards fires is an implementation detail - the transport
    // notices a body that stopped before `Content-Length` and reports a read error,
    // and the byte count in `S3DownloadStream` is the backstop behind it. What must
    // never happen is `Ok(None)`: that is the answer that writes out half a file and
    // calls it a success.
    let err = outcome.expect_err("a body that stopped short must not read as the end of one");

    assert!(received.len() < 64, "got {} bytes", received.len());
    // A cut connection is worth retrying; a 404 is not. The distinction has to survive.
    assert!(err.is_retryable(), "{}", err);
}

/// A streamed download under tracing goes out as the same request - the trace must not
/// reach for the body, which is the one thing it may not read here.
#[tokio::test]
async fn a_streamed_download_survives_debug_mode() {
    let server = FakeS3::start().await;
    let client = server.client().debug_to_console();

    server.push_reply(200, "contents");

    let mut stream = client
        .download_file_as_stream("my-bucket", "a.bin")
        .await
        .unwrap();

    let mut body = Vec::new();
    while let Some(chunk) = stream.get_next_chunk().await.unwrap() {
        body.extend_from_slice(&chunk);
    }

    assert_eq!(body, b"contents");
    assert!(server.captured()[0].signature_valid);
}

// ---------------------------------------------------------------------------
// The harness itself
// ---------------------------------------------------------------------------

/// A test server that agrees with the client is worth nothing. This pins the one thing
/// `FakeS3` has to get *independently* right: a real S3 rebuilds the canonical query by
/// decoding and re-encoding it under RFC 3986, so a client that encoded its query the
/// `x-www-form-urlencoded` way signs a different string from the one the server signs.
///
/// Without this, `fake_s3` took the query off the wire verbatim and would have called a
/// `+`-for-space request correctly signed - the exact bug the client's encoder exists to
/// avoid, validated by a server that shared it.
#[test]
fn the_fake_server_canonicalises_a_query_the_way_a_real_one_does() {
    // A space sent as `+` is not the same canonical string as a space sent as `%20`,
    // which is what makes the wrong encoding a 403 rather than a silent success.
    assert_ne!(
        fake_s3::canonical_query("prefix=a+b"),
        fake_s3::canonical_query("prefix=a%20b")
    );
    assert_eq!(fake_s3::canonical_query("prefix=a+b"), "prefix=a%2Bb");
    assert_eq!(fake_s3::canonical_query("prefix=a%20b"), "prefix=a%20b");

    // `!` is not unreserved, so a client that left it literal signs a different string.
    assert_eq!(fake_s3::canonical_query("k=a!b"), "k=a%21b");
    // `~` is unreserved and must stay literal on both sides.
    assert_eq!(fake_s3::canonical_query("k=a~b"), "k=a~b");

    // Ordering is by encoded name, then encoded value; a valueless flag gets its `=`.
    assert_eq!(fake_s3::canonical_query("b=2&a=1"), "a=1&b=2");
    assert_eq!(fake_s3::canonical_query("location"), "location=");
    assert_eq!(fake_s3::canonical_query(""), "");

    // Re-encoding has to be idempotent for a correctly encoded query, or every one of
    // our requests would fail.
    let ours = "continuation-token=1ueGcxLPRx1Tr%2FXYExHnhbYLgveDs2J%2Fwm36Hy4vbOwM%3D\
&delimiter=%2F&list-type=2&prefix=photos%2F2024%20summer%2F";
    assert_eq!(fake_s3::canonical_query(ours), ours);
}

// ---------------------------------------------------------------------------
// S3Reader - one object as a seekable source
// ---------------------------------------------------------------------------

/// A pattern rather than a constant byte, so that a slice taken at the wrong offset is
/// visibly the wrong slice. 251 is prime, so the period never lines up with a
/// power-of-two page size.
fn object_of(size: usize) -> Vec<u8> {
    (0..size).map(|index| (index % 251) as u8).collect()
}

/// Opening reports the size and costs exactly one request - the `HEAD`.
#[tokio::test]
async fn opening_a_reader_costs_one_head() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(4096));

    let reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    assert_eq!(reader.size(), 4096);
    assert_eq!(reader.position(), 0);

    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].method, "HEAD");
    assert_eq!(captured[0].target, "/my-bucket/a.bin");
    assert!(captured[0].signature_valid);
}

/// `HEAD` on its own, without a reader.
#[tokio::test]
async fn get_object_size_reads_content_length() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(12_345));

    assert_eq!(
        client.get_object_size("my-bucket", "a.bin").await.unwrap(),
        12_345
    );
    assert_eq!(server.captured()[0].method, "HEAD");
}

/// The point of the whole type: seek to an offset, read a page, get *those* bytes.
#[tokio::test]
async fn seek_then_read_exact_returns_the_bytes_at_that_offset() {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let server = FakeS3::start().await;
    let client = server.client();

    let content = object_of(100_000);
    server.put_object("my-bucket", "a.bin", content.clone());

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    let offset = 40_960u64;
    let length = 16 * 1024usize;

    reader.seek(std::io::SeekFrom::Start(offset)).await.unwrap();

    let mut page = vec![0u8; length];
    reader.read_exact(&mut page).await.unwrap();

    assert_eq!(page, content[offset as usize..offset as usize + length]);
    assert_eq!(reader.position(), offset + length as u64);
}

/// One `read_exact` of a page is **one** `GET`, for exactly that range - no read-ahead,
/// no splitting.
#[tokio::test]
async fn one_read_exact_of_a_page_is_one_get() {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(100_000));

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();
    reader.seek(std::io::SeekFrom::Start(3_000)).await.unwrap();

    let mut page = vec![0u8; 3 * 1024];
    reader.read_exact(&mut page).await.unwrap();

    // The HEAD that opened it, and one GET. Nothing else.
    assert_eq!(server.request_count(), 2);

    let captured = server.captured();
    assert_eq!(captured[1].method, "GET");
    assert_eq!(captured[1].target, "/my-bucket/a.bin");
    // Inclusive offsets: 3000 + 3072 - 1.
    assert_eq!(captured[1].header("range"), Some("bytes=3000-6071"));
    assert!(captured[1].signature_valid);
}

/// Reading on from where the last read stopped, without seeking - the sequential case.
#[tokio::test]
async fn consecutive_reads_continue_where_the_last_one_stopped() {
    use tokio::io::AsyncReadExt;

    let server = FakeS3::start().await;
    let client = server.client();

    let content = object_of(10_000);
    server.put_object("my-bucket", "a.bin", content.clone());

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    let mut first = vec![0u8; 100];
    reader.read_exact(&mut first).await.unwrap();

    let mut second = vec![0u8; 100];
    reader.read_exact(&mut second).await.unwrap();

    assert_eq!(first, content[..100]);
    assert_eq!(second, content[100..200]);
    assert_eq!(reader.position(), 200);

    let captured = server.captured();
    assert_eq!(captured.len(), 3);
    assert_eq!(captured[1].header("range"), Some("bytes=0-99"));
    assert_eq!(captured[2].header("range"), Some("bytes=100-199"));
}

/// `Current` and `End` are resolved against the position and the size the `HEAD`
/// reported - neither costs a request.
#[tokio::test]
async fn relative_seeks_land_where_they_should() {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let server = FakeS3::start().await;
    let client = server.client();

    let content = object_of(1_000);
    server.put_object("my-bucket", "a.bin", content.clone());

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    assert_eq!(
        reader.seek(std::io::SeekFrom::Start(100)).await.unwrap(),
        100
    );
    assert_eq!(
        reader.seek(std::io::SeekFrom::Current(50)).await.unwrap(),
        150
    );
    assert_eq!(
        reader.seek(std::io::SeekFrom::Current(-25)).await.unwrap(),
        125
    );
    assert_eq!(reader.seek(std::io::SeekFrom::End(-10)).await.unwrap(), 990);
    assert_eq!(reader.seek(std::io::SeekFrom::End(0)).await.unwrap(), 1_000);

    // Not one request so far: only the HEAD that opened it.
    assert_eq!(server.request_count(), 1);

    // And the position a relative seek left behind is the one that gets read.
    reader.seek(std::io::SeekFrom::End(-4)).await.unwrap();
    let mut tail = [0u8; 4];
    reader.read_exact(&mut tail).await.unwrap();
    assert_eq!(tail.as_slice(), &content[996..]);
}

/// A relative seek is resolved against the position a *read* left behind, not against
/// the last seek.
#[tokio::test]
async fn seek_current_counts_from_where_reading_stopped() {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let server = FakeS3::start().await;
    let client = server.client();

    let content = object_of(1_000);
    server.put_object("my-bucket", "a.bin", content.clone());

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    let mut buffer = [0u8; 40];
    reader.read_exact(&mut buffer).await.unwrap();

    assert_eq!(
        reader.seek(std::io::SeekFrom::Current(10)).await.unwrap(),
        50
    );

    let mut next = [0u8; 4];
    reader.read_exact(&mut next).await.unwrap();
    assert_eq!(next.as_slice(), &content[50..54]);
}

/// Seeking before the start of the object is refused, and refused *without* a request.
#[tokio::test]
async fn seeking_before_the_start_is_invalid_input() {
    use tokio::io::AsyncSeekExt;

    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(1_000));

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    let err = reader
        .seek(std::io::SeekFrom::Current(-1))
        .await
        .unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

    let err = reader
        .seek(std::io::SeekFrom::End(-1_001))
        .await
        .unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

    // The failed seeks left the position alone, and nothing went out.
    assert_eq!(reader.position(), 0);
    assert_eq!(server.request_count(), 1);
}

/// At the end and past it, a read is end-of-file: zero bytes, and **no request** - the
/// size has been known since the `HEAD`. Seeking past the end is allowed, exactly as it
/// is on a file.
#[tokio::test]
async fn reading_at_or_past_the_end_returns_nothing_and_asks_nothing() {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(1_000));

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    reader.seek(std::io::SeekFrom::Start(1_000)).await.unwrap();
    let mut buffer = [0u8; 64];
    assert_eq!(reader.read(&mut buffer).await.unwrap(), 0);

    reader
        .seek(std::io::SeekFrom::Start(10_000_000))
        .await
        .unwrap();
    assert_eq!(reader.read(&mut buffer).await.unwrap(), 0);

    // Still only the HEAD that opened it.
    assert_eq!(server.request_count(), 1);
}

/// A `read_exact` that runs off the end must fail, not come back short: a caller that
/// asked for a page and got half of one would parse the half as the page.
#[tokio::test]
async fn a_read_exact_crossing_the_end_is_unexpected_eof() {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(1_000));

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();
    reader.seek(std::io::SeekFrom::Start(990)).await.unwrap();

    let mut page = [0u8; 64];
    let err = reader.read_exact(&mut page).await.unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);

    // The range that *was* readable was never asked for past the end of the object -
    // that would be a 416 rather than an end of file.
    let captured = server.captured();
    assert_eq!(captured[1].header("range"), Some("bytes=990-999"));
}

/// A `206` that delivers less than the range it acknowledged is a truncation, not a
/// short read.
#[tokio::test]
async fn a_body_shorter_than_the_range_is_unexpected_eof() {
    use tokio::io::AsyncReadExt;

    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(1_000));

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    // Queued after opening, so it answers the GET and not the HEAD.
    server.push_reply(206, "short");

    let mut page = [0u8; 64];
    let err = reader.read_exact(&mut page).await.unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

/// A server that ignores `Range` and returns the whole object is an error, not 64 bytes
/// taken off the front of something else.
#[tokio::test]
async fn a_range_answered_with_200_is_an_error_for_the_reader_too() {
    use tokio::io::AsyncReadExt;

    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(1_000));

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    server.push_reply(200, "the whole object, which is not what was asked for");

    let mut page = [0u8; 64];
    let err = reader.read_exact(&mut page).await.unwrap_err();

    assert!(err.to_string().contains("ignored the Range header"));
}

/// "There is no such object" is answered when the reader is *opened*, and as the typed
/// error - not as an `io::Error` at the first read.
#[tokio::test]
async fn a_missing_key_is_reported_when_the_reader_is_opened() {
    let server = FakeS3::start().await;
    let client = server.client();

    // Something is stored, so the server is serving objects - just not this one.
    server.put_object("my-bucket", "a.bin", object_of(10));

    let err = client
        .open_reader("my-bucket", "missing.bin")
        .await
        .unwrap_err();

    assert!(err.is_key_not_found());
}

/// Same for `get_object_size` on its own: a `HEAD` carries no body, so the bare `404` is
/// all there is to go on.
#[tokio::test]
async fn a_missing_key_has_no_size() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(404, "");

    let err = client
        .get_object_size("my-bucket", "missing.bin")
        .await
        .unwrap_err();

    assert!(err.is_key_not_found());
}

/// Everything that is not a missing key keeps the `S3Error` reachable through the
/// `io::Error`, so a consumer can tell a transport failure from a refusal.
#[tokio::test]
async fn a_failed_read_keeps_the_typed_error_as_its_source() {
    use tokio::io::AsyncReadExt;

    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(1_000));

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    server.push_reply(
        403,
        "<Error><Code>AccessDenied</Code><Message>no</Message></Error>",
    );

    let mut page = [0u8; 64];
    let err = reader.read_exact(&mut page).await.unwrap_err();

    let s3_error = err
        .get_ref()
        .and_then(|err| err.downcast_ref::<my_s3::S3Error>())
        .expect("the S3Error has to survive as the source");

    assert_eq!(s3_error.get_status_code(), Some(403));
    assert!(!s3_error.is_retryable());

    // Nothing that identifies the credentials leaks into the rendered message.
    let rendered = err.to_string();
    assert!(!rendered.contains(fake_s3::ACCESS_KEY));
    assert!(!rendered.contains(fake_s3::SECRET_KEY));
    assert!(!rendered.to_lowercase().contains("signature="));
}

/// Two readers over the same object are two independent positions.
#[tokio::test]
async fn two_readers_do_not_share_a_position() {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let server = FakeS3::start().await;
    let client = server.client();

    let content = object_of(1_000);
    server.put_object("my-bucket", "a.bin", content.clone());

    let mut first = client.open_reader("my-bucket", "a.bin").await.unwrap();
    let mut second = client.open_reader("my-bucket", "a.bin").await.unwrap();

    first.seek(std::io::SeekFrom::Start(10)).await.unwrap();
    second.seek(std::io::SeekFrom::Start(900)).await.unwrap();

    let mut from_first = [0u8; 8];
    let mut from_second = [0u8; 8];
    first.read_exact(&mut from_first).await.unwrap();
    second.read_exact(&mut from_second).await.unwrap();

    assert_eq!(from_first.as_slice(), &content[10..18]);
    assert_eq!(from_second.as_slice(), &content[900..908]);
}

/// `AsyncReadExt` and `AsyncSeekExt` need `Unpin`, and moving a reader onto another
/// tokio task needs `Send`. Both are load-bearing for the consumer, so they are pinned
/// here rather than left to be discovered by a compile error somewhere else.
#[test]
fn a_reader_is_send_and_unpin() {
    fn assert_send_and_unpin<T: Send + Unpin>() {}

    assert_send_and_unpin::<my_s3::S3Reader>();
}

/// And actually move one across a task boundary, which is what a consumer reading pages
/// in a spawned job does.
#[tokio::test]
async fn a_reader_survives_being_moved_to_another_task() {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let server = FakeS3::start().await;
    let client = server.client();

    let content = object_of(1_000);
    server.put_object("my-bucket", "a.bin", content.clone());

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    let page = tokio::spawn(async move {
        reader.seek(std::io::SeekFrom::Start(500)).await.unwrap();
        let mut page = [0u8; 16];
        reader.read_exact(&mut page).await.unwrap();
        page
    })
    .await
    .unwrap();

    assert_eq!(page.as_slice(), &content[500..516]);
}

/// Seeking out from under a request that is still in flight is refused, loudly. The
/// bytes on their way belong to an offset that would no longer exist, and silently
/// dropping the request is the kind of thing that turns into a wrong page much later.
#[tokio::test]
async fn seeking_while_a_read_is_in_flight_is_refused() {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(1_000));

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    // Only now, so the HEAD that opened the reader was not slowed down.
    server.delay_every_reply(Duration::from_millis(500));

    let mut page = [0u8; 8];
    let timed_out =
        tokio::time::timeout(Duration::from_millis(20), reader.read_exact(&mut page)).await;
    assert!(timed_out.is_err(), "the read had to still be in flight");

    let err = reader.seek(std::io::SeekFrom::Start(0)).await.unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::Other);
    assert!(err.to_string().contains("in flight"));
}

/// A read that was cancelled leaves its `GET` in flight. Coming back with a *smaller*
/// buffer must not lose the rest of the range that was already paid for - and must not
/// issue a second `GET` for bytes that are already here.
#[tokio::test]
async fn a_cancelled_read_is_resumed_without_a_second_get() {
    use tokio::io::AsyncReadExt;

    let server = FakeS3::start().await;
    let client = server.client();

    let content = object_of(1_000);
    server.put_object("my-bucket", "a.bin", content.clone());

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    server.delay_every_reply(Duration::from_millis(500));

    // Asks for 16 bytes, then gives up waiting - the GET for bytes=0-15 stays in flight.
    let mut wide = [0u8; 16];
    let timed_out =
        tokio::time::timeout(Duration::from_millis(20), reader.read_exact(&mut wide)).await;
    assert!(timed_out.is_err());

    server.delay_every_reply(Duration::ZERO);

    // Half the buffer this time. The other half of the answer has to be kept, not
    // dropped.
    let mut first = [0u8; 8];
    reader.read_exact(&mut first).await.unwrap();
    assert_eq!(first.as_slice(), &content[..8]);

    let mut second = [0u8; 8];
    reader.read_exact(&mut second).await.unwrap();
    assert_eq!(second.as_slice(), &content[8..16]);

    assert_eq!(reader.position(), 16);

    // The HEAD, and the single GET that was started before the cancellation.
    assert_eq!(server.request_count(), 2);
    assert_eq!(server.captured()[1].header("range"), Some("bytes=0-15"));
}
