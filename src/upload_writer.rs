use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;
use tokio::sync::mpsc::{Receiver, Sender, channel};

/// How much [`S3UploadWriter`] accumulates before a chunk goes out.
///
/// The same order of magnitude as the 256 KiB the streamed-upload examples push by
/// hand: large enough that a producer writing 8 KiB at a time (which is what
/// [`tokio::io::copy`] does) costs one channel send per 64 writes instead of one per
/// write, and small enough that peak memory stays a rounding error next to the object.
pub const DEFAULT_UPLOAD_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// How many finished chunks may sit in the channel before the writer has to wait.
///
/// This is the backpressure, and the reason a 410 MB object never exists in memory: at
/// the default chunk size it bounds what is in flight to ~2 MiB no matter how fast the
/// producer runs or how slow the socket is.
pub(crate) const UPLOAD_CHANNEL_CAPACITY: usize = 4;

/// A chunk on its way into the channel.
///
/// Kept as a future rather than sent inline for the same reason [`crate::S3Reader`]
/// keeps its `GET` that way: a bounded channel's `send` is an `await`, `poll_write` is
/// not, and the send has to survive being polled across several of them.
///
/// `true` means the chunk reached the channel; `false` means the receiving end - the
/// upload - was already gone.
type PendingSend = Pin<Box<dyn Future<Output = bool> + Send>>;

/// State the writer shares with the [`S3Client::upload_with_writer`] call that made it,
/// so that call can tell *why* a producer stopped after the writer has been dropped.
///
/// [`S3Client::upload_with_writer`]: crate::S3Client::upload_with_writer
pub(crate) struct UploadWriterState {
    /// Bytes taken from the producer - buffered or sent, but never more than
    /// `content_length`. What makes "finished early" detectable when the producer
    /// itself reports success.
    accepted: AtomicU64,
    /// Set the first time a send finds the channel closed. That only happens when the
    /// upload has already ended, which makes everything the producer reports afterwards
    /// a consequence rather than a cause.
    upload_ended: AtomicBool,
}

impl UploadWriterState {
    fn new() -> Self {
        Self {
            accepted: AtomicU64::new(0),
            upload_ended: AtomicBool::new(false),
        }
    }

    pub(crate) fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::Acquire)
    }

    pub(crate) fn upload_ended(&self) -> bool {
        self.upload_ended.load(Ordering::Acquire)
    }
}

/// The body of one streamed upload, as a `tokio::io::AsyncWrite`.
///
/// This is [`crate::S3Reader`] the other way round. Code that writes a file - anything
/// shaped like `write_to(&mut impl AsyncWrite)`, or a `tokio::io::copy` out of one -
/// writes an S3 object without an adapter, and without the object ever being in memory.
///
/// A writer is handed to a producer by [`S3Client::upload_with_writer`]; it is not
/// constructed directly, because on its own it is a `Sender` with nobody reading it.
///
/// ```no_run
/// # async fn doc(s3: &my_s3::S3Client, path: &'static str, length: usize)
/// # -> Result<(), my_s3::S3Error> {
/// use tokio::io::AsyncWriteExt;
///
/// s3.upload_with_writer(
///     "my-bucket",
///     "archives/backup.tar",
///     length,
///     std::time::Duration::from_secs(600),
///     |mut writer| async move {
///         let mut file = tokio::fs::File::open(path).await?;
///         tokio::io::copy(&mut file, &mut writer).await?;
///         // Without this the last partial chunk is never sent and the body is short.
///         writer.shutdown().await
///     },
/// )
/// .await
/// # }
/// ```
///
/// # What it costs
///
/// Writes accumulate into a [`DEFAULT_UPLOAD_CHUNK_SIZE`] buffer, and a full chunk goes
/// into a bounded channel that the upload drains. Peak memory is the chunk being filled
/// plus what the channel holds - about 2.5 MiB at the defaults - whatever the size of
/// the object.
///
/// # `shutdown` is not optional
///
/// [`AsyncWriteExt::shutdown`] is what sends the last partial chunk and ends the body.
/// A producer that returns without it delivers fewer bytes than it declared, and
/// [`S3Client::upload_with_writer`] turns that into an error rather than a success -
/// but the error says "finished early", which is a worse thing to read than the missing
/// line.
///
/// # Writing past `content_length` is refused, not truncated
///
/// The length was signed into the request before the first byte existed and HTTP/1.1
/// gives no way to correct it. So the byte that would go past it is refused with
/// [`io::ErrorKind::InvalidInput`] and never sent, rather than quietly dropped: a
/// producer that has miscounted needs to hear about it, and the object it would have
/// written is wrong either way.
///
/// # A dead upload shows up as `BrokenPipe`
///
/// If the upload fails while the producer is still writing, the next write that needs
/// the channel fails with [`io::ErrorKind::BrokenPipe`]. That is a notification, not a
/// diagnosis - the reason the upload died comes from
/// [`S3Client::upload_with_writer`]'s return value, which reports it in preference to
/// the `BrokenPipe` it caused.
///
/// [`S3Client::upload_with_writer`]: crate::S3Client::upload_with_writer
/// [`AsyncWriteExt::shutdown`]: tokio::io::AsyncWriteExt::shutdown
pub struct S3UploadWriter {
    /// For the error messages only - a producer that writes several objects needs to
    /// know which one broke.
    bucket_name: String,
    key: String,
    /// `None` once [`AsyncWrite::poll_shutdown`] has dropped it, which is what
    /// terminates the body. Every clone of it lives inside a [`PendingSend`] and dies
    /// with it, so the body cannot be held open by a send that already finished.
    sender: Option<Sender<Vec<u8>>>,
    /// Bytes accumulated towards the next chunk. Always shorter than `chunk_size`: a
    /// chunk that reaches the size is handed to the channel in the same call.
    buffer: Vec<u8>,
    chunk_size: usize,
    /// The send that has been started but has not been accepted yet. `None` whenever
    /// the channel has room.
    pending: Option<PendingSend>,
    /// Exactly what went into `Content-Length`. Not an estimate, and not adjustable.
    content_length: u64,
    state: Arc<UploadWriterState>,
}

impl S3UploadWriter {
    /// The writer, the body its chunks come out of, and the state the upload reads back.
    ///
    /// Returning all three together is what makes it impossible to build a writer whose
    /// `Receiver` nobody holds - which would fail on the first full chunk, at a place
    /// with no idea why.
    pub(crate) fn new(
        bucket_name: &str,
        key: &str,
        content_length: usize,
        chunk_size: usize,
    ) -> (Self, Receiver<Vec<u8>>, Arc<UploadWriterState>) {
        // A zero chunk size would mean every write is its own channel send, and a
        // `Vec::with_capacity(0)` that grows on every push. Neither is a shape worth
        // supporting, and neither should be a panic in a library.
        let chunk_size = chunk_size.max(1);

        let (sender, receiver) = channel(UPLOAD_CHANNEL_CAPACITY);
        let state = Arc::new(UploadWriterState::new());

        let writer = Self {
            bucket_name: bucket_name.to_string(),
            key: key.to_string(),
            sender: Some(sender),
            buffer: Vec::with_capacity(chunk_size),
            chunk_size,
            pending: None,
            content_length: content_length as u64,
            state: state.clone(),
        };

        (writer, receiver, state)
    }

    /// The `Content-Length` this writer was opened for. Writing past it is an error.
    pub fn content_length(&self) -> u64 {
        self.content_length
    }

    /// How many bytes have been accepted so far - buffered or sent. `content_length`
    /// minus this is what is still owed.
    pub fn bytes_written(&self) -> u64 {
        self.state.accepted()
    }

    /// How much is accumulated before a chunk goes into the channel.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    pub fn bucket_name(&self) -> &str {
        self.bucket_name.as_str()
    }

    pub fn key(&self) -> &str {
        self.key.as_str()
    }

    /// The upload is over and the channel with it. Recorded, because it decides which of
    /// the two errors the caller ends up seeing.
    fn upload_is_gone(&self) -> io::Error {
        self.state.upload_ended.store(true, Ordering::Release);

        io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!(
                "S3UploadWriter: the upload of {}/{} has already ended - its own error says why",
                self.bucket_name, self.key
            ),
        )
    }

    fn already_shut_down(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!(
                "S3UploadWriter: the body of {}/{} was ended by shutdown() and cannot be written to again",
                self.bucket_name, self.key
            ),
        )
    }

    /// Drives a send that was started by an earlier call. `Ready(Ok(()))` means there is
    /// no send outstanding and the channel is free to take another chunk.
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(mut pending) = self.pending.take() else {
            return Poll::Ready(Ok(()));
        };

        match pending.as_mut().poll(cx) {
            Poll::Pending => {
                self.pending = Some(pending);
                Poll::Pending
            }
            Poll::Ready(true) => Poll::Ready(Ok(())),
            Poll::Ready(false) => Poll::Ready(Err(self.upload_is_gone())),
        }
    }

    /// Hands `chunk` to the channel, keeping the send as [`Self::pending`] if it has to
    /// wait for room.
    ///
    /// `Pending` here means the chunk is *held by the writer*, not lost: the next
    /// `poll_write`, `poll_flush` or `poll_shutdown` picks the same send back up.
    fn start_send(&mut self, chunk: Vec<u8>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(sender) = self.sender.clone() else {
            return Poll::Ready(Err(self.already_shut_down()));
        };

        // An owned clone rather than a borrow of `self.sender`: the future has to own
        // everything it touches to be stored in a field, exactly as `S3Reader` boxes its
        // `GET`. It is dropped with the future, so it cannot outlive the send and hold
        // the body open.
        let mut pending: PendingSend = Box::pin(async move { sender.send(chunk).await.is_ok() });

        match pending.as_mut().poll(cx) {
            Poll::Pending => {
                self.pending = Some(pending);
                Poll::Pending
            }
            Poll::Ready(true) => Poll::Ready(Ok(())),
            Poll::Ready(false) => Poll::Ready(Err(self.upload_is_gone())),
        }
    }
}

impl AsyncWrite for S3UploadWriter {
    /// Copies as much of `buf` as fits in the chunk being filled, and sends that chunk
    /// once it is full.
    ///
    /// A partial write is normal here and is what the `chunk_size` cap produces; callers
    /// that want all of it written use `write_all`, which is what `tokio::io::copy`
    /// does.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // A send left over from a previous call, first. Returning `Pending` from here is
        // the only way this function returns without consuming anything, which is what
        // the `AsyncWrite` contract requires of a `Pending`.
        if this.poll_pending(cx)?.is_pending() {
            return Poll::Pending;
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if this.sender.is_none() {
            return Poll::Ready(Err(this.already_shut_down()));
        }

        let accepted = this.state.accepted();
        let owed = this.content_length - accepted;

        // Nothing left to owe and still being written to: the producer has miscounted.
        // Refused before anything is buffered, so not one byte past the declared length
        // ever reaches the channel.
        if owed == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "S3UploadWriter: {}/{} was opened for {} bytes and all of them have been written - {} more were offered",
                    this.bucket_name,
                    this.key,
                    this.content_length,
                    buf.len()
                ),
            )));
        }

        let room_in_chunk = this.chunk_size - this.buffer.len();
        let take = buf.len().min(room_in_chunk).min(owed as usize);

        this.buffer.extend_from_slice(&buf[..take]);
        // Recorded before the send, not after: these bytes are the producer's now
        // whatever happens to the chunk, and a retry re-runs the producer from zero with
        // a fresh writer anyway.
        this.state.accepted.fetch_add(take as u64, Ordering::AcqRel);

        if this.buffer.len() < this.chunk_size {
            return Poll::Ready(Ok(take));
        }

        let chunk = std::mem::replace(&mut this.buffer, Vec::with_capacity(this.chunk_size));

        // The bytes are consumed either way: a send that has to wait is parked in
        // `pending` and picked up by the next call, so reporting `take` here is honest.
        match this.start_send(chunk, cx) {
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(take)),
        }
    }

    /// Sends the partly filled chunk, so that everything written so far is on its way.
    ///
    /// This does **not** wait for those bytes to reach S3 - nothing short of the upload
    /// finishing can promise that - and it does not end the body. Only
    /// [`AsyncWrite::poll_shutdown`] does.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.poll_pending(cx)?.is_pending() {
            return Poll::Pending;
        }

        if this.buffer.is_empty() {
            return Poll::Ready(Ok(()));
        }

        if this.sender.is_none() {
            return Poll::Ready(Err(this.already_shut_down()));
        }

        let chunk = std::mem::replace(&mut this.buffer, Vec::with_capacity(this.chunk_size));

        this.start_send(chunk, cx)
    }

    /// Flushes, then drops the `Sender` - which is what ends the body.
    ///
    /// Idempotent: shutting a writer down twice is not an error, so a producer may call
    /// it in a `finally`-shaped place without tracking whether it already has.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Already shut down: `poll_flush` would refuse a non-empty buffer, and there
        // cannot be one - shutdown only got here by flushing it.
        if self.sender.is_none() {
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();

        if Pin::new(&mut *this).poll_flush(cx)?.is_pending() {
            return Poll::Pending;
        }

        // Dropping it is the end of the body. Every `PendingSend` that held a clone has
        // been polled to completion by the flush above and dropped with it, so this is
        // the last one.
        this.sender = None;

        Poll::Ready(Ok(()))
    }
}

/// Written by hand: the send in flight is a boxed future with no `Debug`, and the
/// buffer is object data that has no business on a console. What is printed is what
/// identifies the writer and how far it has got.
impl std::fmt::Debug for S3UploadWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3UploadWriter")
            .field("bucket_name", &self.bucket_name)
            .field("key", &self.key)
            .field("content_length", &self.content_length)
            .field("bytes_written", &self.bytes_written())
            .field("chunk_size", &self.chunk_size)
            .field("buffered", &self.buffer.len())
            .field("send_in_flight", &self.pending.is_some())
            .field("body_ended", &self.sender.is_none())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod contract_probe {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::task::{RawWaker, RawWakerVTable, Waker};

    static WAKES: AtomicUsize = AtomicUsize::new(0);

    fn counting_waker() -> Waker {
        fn clone(p: *const ()) -> RawWaker { RawWaker::new(p, &VT) }
        fn wake(_: *const ()) { WAKES.fetch_add(1, Ordering::SeqCst); }
        fn wake_by_ref(_: *const ()) { WAKES.fetch_add(1, Ordering::SeqCst); }
        fn drop_it(_: *const ()) {}
        static VT: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop_it);
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VT)) }
    }

    /// Fill the channel (capacity 4) + park a 5th send, then confirm:
    ///  - poll_write never returns Pending having consumed bytes
    ///  - the Pending it does return has a registered waker (draining wakes it)
    ///  - no byte is lost or duplicated
    #[test]
    fn write_never_returns_pending_after_consuming_and_always_registers_a_waker() {
        let chunk = 16usize;
        let total = chunk * 20;
        let (mut w, mut rx, state) = S3UploadWriter::new("b", "k", total, chunk);

        let waker = counting_waker();
        let mut cx = Context::from_waker(&waker);

        let src: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let mut offset = 0usize;
        let mut drained: Vec<u8> = Vec::new();
        let mut pending_rounds = 0;

        while offset < total {
            let before = state.accepted();
            match Pin::new(&mut w).poll_write(&mut cx, &src[offset..]) {
                Poll::Ready(Ok(n)) => {
                    assert!(n > 0, "Ok(0) on a non-empty buf => WriteZero");
                    assert!(n <= total - offset, "reported more than offered");
                    assert_eq!(state.accepted(), before + n as u64, "accepted disagrees with the reported count");
                    offset += n;
                }
                Poll::Pending => {
                    assert_eq!(state.accepted(), before, "PENDING AFTER CONSUMING BYTES");
                    pending_rounds += 1;
                    assert!(pending_rounds < 10_000, "no progress");
                    // The channel is full. Drain one and confirm the waker fires.
                    let wakes_before = WAKES.load(Ordering::SeqCst);
                    let got = rx.blocking_recv().expect("sender alive");
                    drained.extend_from_slice(&got);
                    // give the mpsc a moment to run the waker
                    std::thread::yield_now();
                    assert!(
                        WAKES.load(Ordering::SeqCst) > wakes_before,
                        "NO WAKER REGISTERED on the Pending return"
                    );
                }
                Poll::Ready(Err(e)) => panic!("unexpected error: {}", e),
            }
        }

        // shutdown, draining as needed
        loop {
            match Pin::new(&mut w).poll_shutdown(&mut cx) {
                Poll::Ready(Ok(())) => break,
                Poll::Ready(Err(e)) => panic!("shutdown error: {}", e),
                Poll::Pending => {
                    let got = rx.blocking_recv().expect("sender alive");
                    drained.extend_from_slice(&got);
                }
            }
        }

        while let Ok(got) = rx.try_recv() {
            drained.extend_from_slice(&got);
        }

        assert_eq!(drained.len(), total, "bytes lost or duplicated");
        assert_eq!(drained, src, "byte stream corrupted");
        assert_eq!(state.accepted(), total as u64);

        // idempotent shutdown
        assert!(matches!(Pin::new(&mut w).poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
        assert!(matches!(Pin::new(&mut w).poll_flush(&mut cx), Poll::Ready(Ok(()))));
        // one byte past the end
        let e = match Pin::new(&mut w).poll_write(&mut cx, b"x") {
            Poll::Ready(Err(e)) => e,
            other => panic!("expected an error, got {:?}", other.is_pending()),
        };
        println!("PROBE-C past-end-after-shutdown kind={:?}", e.kind());
    }

    /// content_length exceeded while the writer is still open.
    #[test]
    fn past_content_length_is_invalid_input_and_sends_nothing_extra() {
        let (mut w, mut rx, _state) = S3UploadWriter::new("b", "k", 10, 4);
        let waker = counting_waker();
        let mut cx = Context::from_waker(&waker);

        let mut written = 0;
        let data = vec![7u8; 25];
        let mut got = Vec::new();
        let mut err = None;
        while written < data.len() {
            match Pin::new(&mut w).poll_write(&mut cx, &data[written..]) {
                Poll::Ready(Ok(n)) => written += n,
                Poll::Ready(Err(e)) => { err = Some(e); break; }
                Poll::Pending => { got.extend_from_slice(&rx.blocking_recv().unwrap()); }
            }
        }
        let err = err.expect("must refuse");
        println!("PROBE-C over kind={:?} consumed={}", err.kind(), written);
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(written, 10, "must not consume past content_length");
    }
}
