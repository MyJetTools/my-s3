use std::future::Future;
use std::io::{self, SeekFrom};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

use crate::{S3Client, S3Error};

/// One S3 object as a random-access source: `tokio::io::AsyncRead` +
/// `tokio::io::AsyncSeek`.
///
/// This exists so that code written against `tokio::fs::File` - seek to an offset, read
/// a fixed-size page - reads an object out of S3 without being rewritten. A file format
/// that pages through an index does not need to know whether its bytes are local.
///
/// ```no_run
/// # async fn doc(s3: &my_s3::S3Client) -> Result<(), Box<dyn std::error::Error>> {
/// use tokio::io::{AsyncReadExt, AsyncSeekExt};
///
/// let mut reader = s3.open_reader("my-bucket", "index.dat").await?;
///
/// let mut page = vec![0u8; 16 * 1024];
/// reader.seek(std::io::SeekFrom::Start(4 * 16 * 1024)).await?;
/// reader.read_exact(&mut page).await?;
/// # Ok(())
/// # }
/// ```
///
/// # What it costs
///
/// Opening it is **one `HEAD`**, for the size. After that, seeking is free - it moves a
/// number and makes no request - and each `poll_read` is **exactly one ranged `GET`**
/// for `min(what the caller asked for, what is left in the object)` bytes. Nothing is
/// read ahead and nothing is cached, so a `read_exact` of a 16 KiB page is one `GET` of
/// 16 KiB, and the object is never held in memory whatever its size.
///
/// That also means this is the wrong shape for reading an object front to back in small
/// pieces - that is one request per piece. [`S3Client::download_file_as_stream`] is the
/// shape for that.
///
/// # One reader is one position
///
/// A reader has a single position and one request in flight at a time, like a file
/// handle. Reading two places at once is two readers - opening another one costs another
/// `HEAD` but they are then completely independent.
///
/// # A short answer is an error
///
/// A body shorter than the range that was asked for comes back as
/// [`io::ErrorKind::UnexpectedEof`], never as a short read. A consumer that asked for a
/// page and silently got half of one would parse the half as though it were the page.
pub struct S3Reader {
    /// Cloned out of the [`S3Client`] that opened this reader, so the request future
    /// can own everything it touches and stay `'static`.
    client: Arc<S3Client>,
    bucket_name: String,
    key: String,
    /// From the `HEAD` at open time. Fixed for the life of the reader: an object that is
    /// overwritten underneath a reader is a changed object, and pretending otherwise
    /// would mean re-`HEAD`ing on every read.
    size: u64,
    /// The offset of the next byte the caller will be handed.
    position: u64,
    /// The `GET` that has been started but has not answered yet. `None` between reads.
    pending: Option<PendingRead>,
    /// The tail of a range that was already fetched but did not fit in the buffer the
    /// caller came back with.
    ///
    /// This is **not** read-ahead: no request ever asks for more than the caller did. It
    /// only exists because `poll_read` may be handed a *smaller* buffer than the one the
    /// in-flight request was sized for - which is what happens when a read is cancelled
    /// (a `select!` that timed out) and a later, shorter read polls the same request to
    /// completion. Dropping those bytes would be a silent hole in the object.
    leftover: Vec<u8>,
    /// The absolute offset `start_seek` resolved, waiting for `poll_complete` to apply
    /// it. `AsyncSeek` is a two-call trait even when, as here, seeking does no work.
    seek_to: Option<u64>,
}

/// A ranged `GET` in flight, with the length it was asked for.
///
/// The length has to be kept next to the future: it is decided when the request starts
/// and checked when it answers, and those are different `poll_read` calls.
struct PendingRead {
    future: Pin<Box<dyn Future<Output = Result<Vec<u8>, S3Error>> + Send>>,
    requested: usize,
}

impl S3Reader {
    pub(crate) fn new(client: Arc<S3Client>, bucket_name: String, key: String, size: u64) -> Self {
        Self {
            client,
            bucket_name,
            key,
            size,
            position: 0,
            pending: None,
            leftover: Vec::new(),
            seek_to: None,
        }
    }

    /// The object's size, as the `HEAD` at open time reported it.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The offset of the next byte a read would return.
    ///
    /// Available without `AsyncSeekExt::stream_position`, and without its `&mut self`.
    pub fn position(&self) -> u64 {
        self.position
    }

    pub fn bucket_name(&self) -> &str {
        self.bucket_name.as_str()
    }

    pub fn key(&self) -> &str {
        self.key.as_str()
    }

    /// Hands over as much of [`Self::leftover`] as fits, and advances the position by
    /// exactly that much.
    fn drain_leftover(&mut self, buf: &mut ReadBuf<'_>) {
        let taken = self.leftover.len().min(buf.remaining());

        buf.put_slice(&self.leftover[..taken]);
        self.leftover.drain(..taken);
        self.position += taken as u64;
    }

    /// Starts the one ranged `GET` this read needs.
    ///
    /// `requested` is `min(buffer, what is left)` - never more than the caller asked for
    /// and never past the end of the object, so a well-formed reader cannot produce the
    /// `416` that reading past the end would otherwise be.
    fn start_read(&mut self, buf: &ReadBuf<'_>) -> PendingRead {
        let requested = (buf.remaining() as u64).min(self.size - self.position) as usize;

        let start = self.position;
        // `download_file_range` takes inclusive offsets, the way the HTTP `Range` header
        // does.
        let end = start + requested as u64 - 1;

        let client = self.client.clone();
        let bucket_name = self.bucket_name.clone();
        let key = self.key.clone();

        PendingRead {
            future: Box::pin(async move {
                client
                    .download_file_range(bucket_name.as_str(), key.as_str(), start, Some(end))
                    .await
            }),
            requested,
        }
    }
}

impl AsyncRead for S3Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Bytes a request already paid for, before asking for anything new.
        if !this.leftover.is_empty() {
            this.drain_leftover(buf);
            return Poll::Ready(Ok(()));
        }

        // `take()` rather than `as_mut()`: the future has to be polled and the slot
        // cleared in the same call, and holding a borrow across both is what the borrow
        // checker refuses.
        let mut pending = match this.pending.take() {
            Some(pending) => pending,
            None => {
                // At or past the end of the object: end of file, and no request made to
                // discover that - the size has been known since the `HEAD`. A file
                // behaves the same way, which is the whole point of this type.
                if this.position >= this.size || buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }

                this.start_read(buf)
            }
        };

        let requested = pending.requested;

        let result = match pending.future.as_mut().poll(cx) {
            Poll::Pending => {
                this.pending = Some(pending);
                return Poll::Pending;
            }
            Poll::Ready(result) => result,
        };

        let body = match result {
            Ok(body) => body,
            Err(err) => return Poll::Ready(Err(to_io_error(err))),
        };

        // A `206` that delivered less than the range it acknowledged. Handing this back
        // as a short read is how a half-read page gets parsed as a whole one.
        if body.len() < requested {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "S3Reader: asked {}/{} for {} bytes at offset {} and the body was {} bytes",
                    this.bucket_name,
                    this.key,
                    requested,
                    this.position,
                    body.len()
                ),
            )));
        }

        // More than was asked for means the storage answered a different range than the
        // one requested; the position it belongs to is then unknowable.
        if body.len() > requested {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "S3Reader: asked {}/{} for {} bytes at offset {} and the body was {} bytes",
                    this.bucket_name,
                    this.key,
                    requested,
                    this.position,
                    body.len()
                ),
            )));
        }

        this.leftover = body;
        this.drain_leftover(buf);

        Poll::Ready(Ok(()))
    }
}

/// Seeking makes no request: the position is a number, and [`AsyncRead::poll_read`] is
/// what turns it into a `Range`.
///
/// Seeking **past the end is allowed**, exactly as it is on a file - it is reading there
/// that returns nothing. Seeking before the start is
/// [`io::ErrorKind::InvalidInput`].
impl AsyncSeek for S3Reader {
    fn start_seek(self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        let this = self.get_mut();

        // Moving the position out from under a request in flight would mean the bytes
        // now on their way belong to an offset that no longer exists. Refusing is louder
        // than dropping the request, and a reader is a single position by design - this
        // only comes up when a cancelled read was never polled to completion.
        if this.pending.is_some() {
            return Err(io::Error::other(
                "S3Reader: cannot seek while a read is still in flight - poll the read to completion before seeking",
            ));
        }

        if this.seek_to.is_some() {
            return Err(io::Error::other(
                "S3Reader: a seek is already in progress - poll_complete it before starting another",
            ));
        }

        let target = match position {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(delta) => resolve_offset(this.position, delta, "current position")?,
            SeekFrom::End(delta) => resolve_offset(this.size, delta, "end of the object")?,
        };

        this.seek_to = Some(target);

        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        let this = self.get_mut();

        // Called without a `start_seek` this is `stream_position()` - answer where we
        // are and change nothing.
        if let Some(target) = this.seek_to.take() {
            this.position = target;
            // Whatever was fetched belongs to the position we just left.
            this.leftover.clear();
        }

        Poll::Ready(Ok(this.position))
    }
}

/// Applies a relative seek, in `i128` so that neither the addition nor the comparison
/// can wrap - `u64::MAX` as a base and `i64::MIN` as a delta both fit.
fn resolve_offset(base: u64, delta: i64, base_name: &str) -> io::Result<u64> {
    let target = base as i128 + delta as i128;

    if target < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "S3Reader: seeking {} from the {} ({}) lands at {}, before the start of the object",
                delta, base_name, base, target
            ),
        ));
    }

    if target > u64::MAX as i128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "S3Reader: seeking {} from the {} ({}) overflows a 64-bit offset",
                delta, base_name, base
            ),
        ));
    }

    Ok(target as u64)
}

/// Turns an [`S3Error`] into the `io::Error` the `AsyncRead` contract requires, without
/// throwing the typed error away.
///
/// A missing key becomes [`io::ErrorKind::NotFound`], because to a consumer that opens
/// objects by name that is the same answer a missing file gives.
///
/// Everything else keeps the `S3Error` as the error's `source`, so a caller can tell a
/// network failure apart from a permissions one:
///
/// ```no_run
/// # fn doc(err: &std::io::Error) {
/// if let Some(err) = err.get_ref().and_then(|err| err.downcast_ref::<my_s3::S3Error>()) {
///     if err.is_retryable() {
///         // a transport failure, not a refusal - try again
///     }
/// }
/// # }
/// ```
///
/// Neither the access key nor the signature reaches the message: `S3Error`'s `Display`
/// carries the status code and the storage's `<Error><Code>`, and the signature travels
/// in a header that is never rendered.
pub(crate) fn to_io_error(err: S3Error) -> io::Error {
    if err.is_key_not_found() {
        return io::Error::new(io::ErrorKind::NotFound, err);
    }

    io::Error::other(err)
}

/// Written by hand: the request in flight is a boxed future and has no `Debug` of its
/// own. What is printed is what identifies the reader and where it is - not the bytes it
/// happens to be holding, and never the client, which carries the credentials.
impl std::fmt::Debug for S3Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Reader")
            .field("bucket_name", &self.bucket_name)
            .field("key", &self.key)
            .field("size", &self.size)
            .field("position", &self.position)
            .field("read_in_flight", &self.pending.is_some())
            .finish_non_exhaustive()
    }
}
