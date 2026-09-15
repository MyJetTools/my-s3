use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;
use tokio::sync::Notify;
use tokio::sync::mpsc::{Receiver, Sender, channel};

use crate::S3Error;

/// How much [`S3UploadWriter`] accumulates before a chunk goes out.
///
/// The same order of magnitude as the 256 KiB the streamed-upload examples push by
/// hand: large enough that a producer writing 8 KiB at a time (which is what
/// [`tokio::io::copy`] does) costs one channel send per 64 writes instead of one per
/// write, and small enough that peak memory stays a rounding error next to the object.
pub const DEFAULT_UPLOAD_CHUNK_SIZE: usize = 512 * 1024;

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

/// State the writer shares with whoever settles the upload - the
/// [`S3Client::upload_with_writer`] call that made it, or the [`S3UploadHandle`] that
/// [`S3Client::start_upload`] handed out - so the outcome can be told apart from its
/// consequences after the writer is gone.
///
/// [`S3Client::upload_with_writer`]: crate::S3Client::upload_with_writer
/// [`S3Client::start_upload`]: crate::S3Client::start_upload
/// [`S3UploadHandle`]: crate::S3UploadHandle
pub(crate) struct UploadWriterState {
    /// Exactly what went into `Content-Length`. Not an estimate, and not adjustable.
    /// Kept here rather than on the writer so that the writer's cap and every verdict
    /// about the body are measured against one number.
    content_length: u64,
    /// Bytes taken from the producer - buffered or sent, but never more than
    /// `content_length`. What the `content_length` cap in `poll_write` is measured
    /// against.
    accepted: AtomicU64,
    /// Bytes that reached the channel, i.e. that the upload could actually send. This,
    /// not `accepted`, is what says whether the body was delivered: a partial chunk
    /// left in the buffer by a producer that never called `shutdown` has been
    /// accepted and has gone nowhere.
    sent: AtomicU64,
    /// Set the first time a send finds the channel closed. That only happens when the
    /// upload has already ended, which makes everything the producer reports afterwards
    /// a consequence rather than a cause.
    upload_ended: AtomicBool,
    /// Set when the writer ends the body - by `shutdown`, or by being dropped - and
    /// always *before* its `Sender` goes, so the upload, which learns of the end through
    /// the channel, can never see the end without this.
    ///
    /// Until it is set a short `sent` says nothing about the writer: it may simply
    /// still be writing. `upload_with_writer` never needs it, because it waits for the
    /// producer before it settles; [`S3UploadHandle::finish`] does not wait for the
    /// writer, and cannot blame one that is still alive.
    ///
    /// [`S3UploadHandle::finish`]: crate::S3UploadHandle::finish
    body_ended: AtomicBool,
    /// Fired when the first chunk is handed to the channel or the body ends, whichever
    /// comes first. [`S3Client::start_upload`] holds the request back until then, so a
    /// writer taken early and written late does not keep a socket open - or a timeout
    /// running - while it has nothing to send.
    ///
    /// A `Notify` stores one permit when nobody is waiting yet, so firing before the
    /// upload task gets to wait is not a lost wake-up. Nothing waits on it for
    /// `upload_with_writer`, whose request starts at once; the permit is simply never
    /// taken.
    ///
    /// [`S3Client::start_upload`]: crate::S3Client::start_upload
    body_started: Notify,
}

impl UploadWriterState {
    fn new(content_length: u64) -> Self {
        Self {
            content_length,
            accepted: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            upload_ended: AtomicBool::new(false),
            body_ended: AtomicBool::new(false),
            body_started: Notify::new(),
        }
    }

    pub(crate) fn content_length(&self) -> u64 {
        self.content_length
    }

    pub(crate) fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::Acquire)
    }

    pub(crate) fn sent(&self) -> u64 {
        self.sent.load(Ordering::Acquire)
    }

    pub(crate) fn upload_ended(&self) -> bool {
        self.upload_ended.load(Ordering::Acquire)
    }

    pub(crate) fn body_ended(&self) -> bool {
        self.body_ended.load(Ordering::Acquire)
    }

    /// Resolves once the writer has something for the request to carry - its first
    /// chunk, or the end of the body.
    pub(crate) async fn body_started(&self) {
        self.body_started.notified().await
    }

    fn mark_body_started(&self) {
        self.body_started.notify_one();
    }

    /// Recorded, then announced: an upload waiting for its first chunk must be released
    /// by a body that ends without one, or it waits for a writer that no longer exists.
    fn mark_body_ended(&self) {
        self.body_ended.store(true, Ordering::Release);
        self.body_started.notify_one();
    }

    /// `Some` when fewer bytes reached the channel than were declared.
    ///
    /// Measured by `sent`, not `accepted`: a partial chunk still sitting in the writer's
    /// buffer went nowhere, whatever the writer was told.
    pub(crate) fn short_body_error(&self) -> Option<io::Error> {
        let delivered = self.sent();

        if delivered >= self.content_length {
            return None;
        }

        Some(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "only {} of the {} bytes declared for the upload body went out - the writer was dropped early or shutdown() was not called, or the source ended early",
                delivered, self.content_length
            ),
        ))
    }

    /// Decides which of two failures the caller sees - for [`S3Client::upload_with_writer`]
    /// and [`S3UploadHandle::finish`] alike, so the two cannot drift apart.
    ///
    /// An upload written through a writer has two halves that fail *together*: kill
    /// either one and the other stops right after, with an error that describes the
    /// wreckage rather than the cause. So the rule is about order, not about which error
    /// looks worse:
    ///
    /// > If the writer saw the channel close under it, the upload died first and
    /// > everything reported about the body is downstream of that - the S3 error is the
    /// > one that explains the failure. Otherwise the body failed on its own, and the S3
    /// > error is only "the body was shorter than `Content-Length`", which explains
    /// > nothing.
    ///
    /// A body that was ended having delivered less than it declared is a failure of the
    /// same kind, and is caught here rather than left to the storage: the storage would
    /// report it as a malformed request, or - with an unlucky server - not at all.
    /// `body_failure` is where that arrives, through [`Self::short_body_error`], next to
    /// whatever a producer returned.
    ///
    /// [`S3Client::upload_with_writer`]: crate::S3Client::upload_with_writer
    /// [`S3UploadHandle::finish`]: crate::S3UploadHandle::finish
    pub(crate) fn settle(
        &self,
        upload_result: Result<(), S3Error>,
        body_failure: Option<io::Error>,
    ) -> Result<(), S3Error> {
        match (upload_result, body_failure) {
            (Ok(()), None) => Ok(()),

            // The storage accepted a body the writer did not finish. Whether a server can
            // actually answer this way or not, it is not something to return as success.
            (Ok(()), Some(err)) => Err(S3Error::UploadProducerFailed(err)),

            (Err(err), None) => Err(err),

            (Err(s3_error), Some(body_error)) => {
                if self.upload_ended() {
                    Err(s3_error)
                } else {
                    Err(S3Error::UploadProducerFailed(body_error))
                }
            }
        }
    }
}

/// The body of one streamed upload, as a `tokio::io::AsyncWrite`.
///
/// This is [`crate::S3Reader`] the other way round. Code that writes a file - anything
/// shaped like `write_to(&mut impl AsyncWrite)`, or a `tokio::io::copy` out of one -
/// writes an S3 object without an adapter, and without the object ever being in memory.
///
/// A writer is handed out by [`S3Client::upload_with_writer`] or
/// [`S3Client::start_upload`]; it is not constructed directly, because on its own it is a
/// `Sender` with nobody reading it.
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
/// into a bounded channel that the upload drains. Peak memory is a handful of chunks -
/// the four queued in the channel, one waiting to join them, the one the HTTP client is
/// writing, and the buffer being filled - at most about 3.5 MiB at the defaults,
/// whatever the size of the object.
///
/// # End with `shutdown`
///
/// [`AsyncWriteExt::shutdown`] sends the last partial chunk and ends the body. It is the
/// only ending that does not depend on how the producer happened to write: dropping the
/// writer also ends the body, but sends nothing first, so a producer that returns with
/// a partial chunk still buffered has delivered fewer bytes than it declared.
/// [`S3Client::upload_with_writer`] and [`S3UploadHandle::finish`] report that as an
/// error, never as a success - but as "only N of M bytes went out", which is a worse
/// thing to read than the missing line.
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
/// [`S3Client::upload_with_writer`]'s return value, or from [`S3UploadHandle::finish`],
/// both of which report it in preference to the `BrokenPipe` it caused.
///
/// [`S3Client::upload_with_writer`]: crate::S3Client::upload_with_writer
/// [`S3Client::start_upload`]: crate::S3Client::start_upload
/// [`S3UploadHandle::finish`]: crate::S3UploadHandle::finish
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
    /// `content_length` lives here, with everything the upload reads back.
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
        let state = Arc::new(UploadWriterState::new(content_length as u64));

        let writer = Self {
            bucket_name: bucket_name.to_string(),
            key: key.to_string(),
            sender: Some(sender),
            buffer: Vec::with_capacity(chunk_size),
            chunk_size,
            pending: None,
            state: state.clone(),
        };

        (writer, receiver, state)
    }

    /// The `Content-Length` this writer was opened for. Writing past it is an error.
    pub fn content_length(&self) -> u64 {
        self.state.content_length()
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

        // There is something to carry now, so a request held back for it may start.
        // Before the send rather than after: the send may well be what waits for it.
        self.state.mark_body_started();

        // An owned clone rather than a borrow of `self.sender`: the future has to own
        // everything it touches to be stored in a field, exactly as `S3Reader` boxes its
        // `GET`. It is dropped with the future, so it cannot outlive the send and hold
        // the body open.
        // Counted inside the send, by the send: a chunk is delivered exactly when the
        // channel takes it, and that moment belongs to whichever `poll_*` call happens
        // to drive the future there.
        let state = self.state.clone();

        let mut pending: PendingSend = Box::pin(async move {
            let length = chunk.len() as u64;

            if sender.send(chunk).await.is_err() {
                return false;
            }

            state.sent.fetch_add(length, Ordering::AcqRel);
            true
        });

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

        // A send has already found the channel closed. Every later write is refused with
        // the same `BrokenPipe`, rather than whatever the byte count happens to make of
        // it - a producer that ignores the first one and keeps writing past the end
        // must not be told it miscounted.
        if this.state.upload_ended() {
            return Poll::Ready(Err(this.upload_is_gone()));
        }

        let content_length = this.state.content_length();
        let accepted = this.state.accepted();
        let owed = content_length - accepted;

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
                    content_length,
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

        // Recorded before the `Sender` goes, so the upload cannot see the end of the body
        // without it.
        this.state.mark_body_ended();

        // Dropping it is the end of the body. Every `PendingSend` that held a clone has
        // been polled to completion by the flush above and dropped with it, so this is
        // the last one.
        this.sender = None;

        Poll::Ready(Ok(()))
    }
}

/// Dropping a writer ends the body too, just without sending what is still buffered.
///
/// It has to be *recorded* as the end: the handle from [`S3Client::start_upload`] reads
/// a short body as the writer's failure only once the body has ended, and an upload still
/// waiting for its first chunk has to be released rather than left waiting for a writer
/// that no longer exists.
///
/// The `Sender` is dropped with the fields, after this runs - the same order
/// `poll_shutdown` keeps. A send left in `pending` dies with them without having
/// delivered its chunk, so `sent` is already final here.
///
/// [`S3Client::start_upload`]: crate::S3Client::start_upload
impl Drop for S3UploadWriter {
    fn drop(&mut self) {
        if self.sender.is_some() {
            self.state.mark_body_ended();
        }
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
            .field("content_length", &self.content_length())
            .field("bytes_written", &self.bytes_written())
            .field("chunk_size", &self.chunk_size)
            .field("buffered", &self.buffer.len())
            .field("send_in_flight", &self.pending.is_some())
            .field("body_ended", &self.sender.is_none())
            .finish_non_exhaustive()
    }
}
