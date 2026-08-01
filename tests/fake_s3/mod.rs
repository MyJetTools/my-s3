//! A minimal S3-compatible server that runs in the test process.
//!
//! The point is to drive the real client through a real socket, so the things that only
//! exist on the wire get checked: the SigV4 signature, the exact request target, the
//! framing headers, and the status codes. It deliberately re-derives the signature with
//! its own code rather than calling into `my_s3` - a test that shares the
//! implementation would agree with any bug in it.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

type HmacSha256 = Hmac<Sha256>;

pub const ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
pub const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
pub const REGION: &str = "fsn1";

/// Everything one request looked like once it arrived.
#[derive(Debug, Clone)]
pub struct Captured {
    pub method: String,
    /// The request target exactly as it came off the wire, e.g. `/bucket/a/b.bin`.
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Whether the `Authorization` header verifies against the body and headers as
    /// received.
    pub signature_valid: bool,
}

impl Captured {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn has_header(&self, name: &str) -> bool {
        self.header(name).is_some()
    }
}

struct State {
    /// Replies to hand out in order; an empty queue means "200 with no body".
    replies: Mutex<VecDeque<(u16, String)>>,
    captured: Mutex<Vec<Captured>>,
}

pub struct FakeS3 {
    pub endpoint: String,
    state: Arc<State>,
}

impl FakeS3 {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let state = Arc::new(State {
            replies: Mutex::new(VecDeque::new()),
            captured: Mutex::new(Vec::new()),
        });

        let accept_state = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };

                let connection_state = accept_state.clone();
                tokio::spawn(async move {
                    // Keep-alive: FlUrl pools connections, so one socket carries
                    // several requests.
                    let _ = serve_connection(stream, connection_state).await;
                });
            }
        });

        Self {
            endpoint: format!("http://{}", addr),
            state,
        }
    }

    /// Queues the next reply. Without this the server answers 200 with an empty body.
    pub fn push_reply(&self, status_code: u16, body: &str) {
        self.state
            .replies
            .lock()
            .unwrap()
            .push_back((status_code, body.to_string()));
    }

    pub fn captured(&self) -> Vec<Captured> {
        self.state.captured.lock().unwrap().clone()
    }

    pub fn request_count(&self) -> usize {
        self.state.captured.lock().unwrap().len()
    }

    pub fn client(&self) -> my_s3::S3Client {
        my_s3::S3Client {
            access_key: ACCESS_KEY.to_string(),
            secret_key: SECRET_KEY.to_string(),
            region: REGION.to_string(),
            endpoint: self.endpoint.clone(),
        }
    }
}

async fn serve_connection(
    mut stream: tokio::net::TcpStream,
    state: Arc<State>,
) -> std::io::Result<()> {
    let mut buffer = Vec::new();

    loop {
        // Read until the end of the header block.
        let header_end = loop {
            if let Some(index) = find_subslice(&buffer, b"\r\n\r\n") {
                break index;
            }

            let mut chunk = [0u8; 8192];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..read]);
        };

        let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
        let mut lines = head.split("\r\n");

        let request_line = lines.next().unwrap_or_default().to_string();
        let mut request_line_parts = request_line.split(' ');
        let method = request_line_parts.next().unwrap_or_default().to_string();
        let target = request_line_parts.next().unwrap_or_default().to_string();

        let mut headers = Vec::new();
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_string(), value.trim().to_string()));
            }
        }

        let content_length: usize = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.parse().ok())
            .unwrap_or(0);

        let is_chunked = headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        });

        buffer.drain(..header_end + 4);

        let body = if is_chunked {
            read_chunked_body(&mut stream, &mut buffer).await?
        } else {
            while buffer.len() < content_length {
                let mut chunk = [0u8; 8192];
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            let taken = buffer.len().min(content_length);
            buffer.drain(..taken).collect()
        };

        let signature_valid = verify_signature(&method, &target, &headers, &body);

        state.captured.lock().unwrap().push(Captured {
            method,
            target,
            headers,
            body,
            signature_valid,
        });

        let (status_code, reply_body) = state
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or((200, String::new()));

        write_response(&mut stream, status_code, &reply_body).await?;
    }
}

async fn read_chunked_body(
    stream: &mut tokio::net::TcpStream,
    buffer: &mut Vec<u8>,
) -> std::io::Result<Vec<u8>> {
    let mut body = Vec::new();

    loop {
        // One chunk size line, then that many bytes, then CRLF.
        let line_end = loop {
            if let Some(index) = find_subslice(buffer, b"\r\n") {
                break index;
            }
            let mut chunk = [0u8; 8192];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok(body);
            }
            buffer.extend_from_slice(&chunk[..read]);
        };

        let size_line = String::from_utf8_lossy(&buffer[..line_end]).into_owned();
        buffer.drain(..line_end + 2);

        let size =
            usize::from_str_radix(size_line.trim().split(';').next().unwrap_or_default(), 16)
                .unwrap_or(0);

        if size == 0 {
            // Trailing CRLF after the terminating chunk.
            while buffer.len() < 2 {
                let mut chunk = [0u8; 8192];
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            let taken = buffer.len().min(2);
            buffer.drain(..taken);
            return Ok(body);
        }

        while buffer.len() < size + 2 {
            let mut chunk = [0u8; 8192];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
        }

        let taken = buffer.len().min(size);
        body.extend(buffer.drain(..taken));
        let trailing = buffer.len().min(2);
        buffer.drain(..trailing);
    }
}

async fn write_response(
    stream: &mut tokio::net::TcpStream,
    status_code: u16,
    body: &str,
) -> std::io::Result<()> {
    let reason = match status_code {
        200 => "OK",
        204 => "No Content",
        206 => "Partial Content",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        416 => "Range Not Satisfiable",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Unknown",
    };

    // 204 carries no content at all - not even a zero Content-Length - which is exactly
    // the shape a client that only accepts 200 used to trip over.
    let response = if status_code == 204 {
        format!("HTTP/1.1 204 {}\r\nConnection: keep-alive\r\n\r\n", reason)
    } else {
        format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: application/xml\r\nConnection: keep-alive\r\n\r\n{}",
            status_code,
            reason,
            body.len(),
            body
        )
    };

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

/// Recomputes the SigV4 signature from the request as received and compares it with the
/// one in `Authorization`.
fn verify_signature(method: &str, target: &str, headers: &[(String, String)], body: &[u8]) -> bool {
    let get = |name: &str| -> Option<&str> {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };

    let Some(authorization) = get("authorization") else {
        return false;
    };
    let Some(host) = get("host") else {
        return false;
    };
    let Some(payload_hash) = get("x-amz-content-sha256") else {
        return false;
    };
    let Some(timestamp) = get("x-amz-date") else {
        return false;
    };

    // A signed payload must actually hash to what the header claims. UNSIGNED-PAYLOAD
    // opts out of that by design, which is why the streamed path uses it.
    if payload_hash != "UNSIGNED-PAYLOAD" && hex::encode(Sha256::digest(body)) != payload_hash {
        return false;
    }

    let Some(signature_part) = authorization.split("Signature=").nth(1) else {
        return false;
    };
    let expected_signature = signature_part.trim();

    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };

    let canonical_query = match query {
        Some(query) if !query.is_empty() => {
            let mut pairs: Vec<(&str, &str)> = query
                .split('&')
                .filter(|pair| !pair.is_empty())
                .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
                .collect();
            pairs.sort_unstable();
            pairs
                .iter()
                .map(|(name, value)| format!("{}={}", name, value))
                .collect::<Vec<_>>()
                .join("&")
        }
        _ => String::new(),
    };

    let canonical_request = format!(
        "{}\n{}\n{}\nhost:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n\nhost;x-amz-content-sha256;x-amz-date\n{}",
        method, path, canonical_query, host, payload_hash, timestamp, payload_hash
    );

    let date = &timestamp[..8];
    let scope = format!("{}/{}/s3/aws4_request", date, REGION);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        timestamp,
        scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let signing_key = derive_signing_key(SECRET_KEY, date, REGION, "s3");
    let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
    mac.update(string_to_sign.as_bytes());

    hex::encode(mac.finalize().into_bytes()) == expected_signature
}

fn derive_signing_key(secret_key: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let mut key = format!("AWS4{}", secret_key).into_bytes();

    for part in [date, region, service, "aws4_request"] {
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(part.as_bytes());
        key = mac.finalize().into_bytes().to_vec();
    }

    key
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
