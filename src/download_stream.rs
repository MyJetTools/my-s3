use crate::S3Error;

/// An object's body, handed over a chunk at a time instead of as one `Vec<u8>`.
///
/// [`S3Client::download_file`](crate::S3Client::download_file) has to hold the whole
/// object in memory before the caller sees the first byte of it, which is fine for a
/// settings file and is a way to be killed by the OOM killer for a video. This is the
/// other shape: peak memory is one chunk, whatever the object's size, so a server can
/// forward an object it could never hold.
///
/// The connection is checked out for as long as this value lives. Read it to the end -
/// `get_next_chunk` returning `Ok(None)` - and the connection goes back to the pool;
/// drop it early and the connection is disposed of, which is correct but costs a
/// handshake on the next request.
///
/// ```no_run
/// # async fn doc(s3: &my_s3::S3Client) -> Result<(), my_s3::S3Error> {
/// let mut stream = s3.download_file_as_stream("my-bucket", "video.mp4").await?;
///
/// // Both are what an HTTP response would need in order to forward this.
/// let _ = stream.content_length;
/// let _ = stream.content_type.as_deref();
///
/// while let Some(chunk) = stream.get_next_chunk().await? {
///     // write it out - this is the only copy of the object in memory
///     let _ = chunk;
/// }
/// # Ok(())
/// # }
/// ```
pub struct S3DownloadStream {
    /// The object's size, from `Content-Length`. `None` when the storage answered with
    /// a chunked body and did not state one.
    pub content_length: Option<u64>,
    /// The object's `Content-Type` as stored. `None` when the storage did not send one.
    pub content_type: Option<String>,

    /// The body, still on the socket. Kept private: `flurl` is this crate's
    /// implementation detail, and a `FlResponseAsStream` in the signature would make
    /// every consumer depend on the same `flurl` version this crate happens to pin.
    stream: flurl::FlResponseAsStream,

    /// Bytes handed to the caller so far, so the end of the stream can be checked
    /// against `content_length` rather than trusted.
    received: u64,
}

impl S3DownloadStream {
    pub(crate) fn from_response(response: flurl::FlUrlResponse) -> Self {
        // Both headers have to be read *before* the body is taken, because
        // `get_body_as_stream` consumes the response. Owning the values here (a `u64`
        // and a `String`) is what ends the borrow in time.
        //
        // Case-insensitively: HTTP header names are, and an S3-compatible storage is
        // free to answer `Content-Length` or `content-length`.
        let content_length = response
            .get_header_case_insensitive("content-length")
            .ok()
            .flatten()
            .and_then(|value| value.trim().parse::<u64>().ok());

        let content_type = response
            .get_header_case_insensitive("content-type")
            .ok()
            .flatten()
            .map(|value| value.to_string());

        Self {
            content_length,
            content_type,
            stream: response.get_body_as_stream(),
            received: 0,
        }
    }

    /// The next chunk, or `Ok(None)` once the object has been delivered in full.
    ///
    /// Chunk sizes are the socket's, not a size this crate picks: expect them to vary
    /// and do not treat one as a record boundary.
    ///
    /// # A short body is an error
    ///
    /// A connection that breaks in the middle of an object must not look like the end of
    /// it - that is how a truncated file gets written out and believed to be whole.
    ///
    /// The transport catches this first: a body that stops before `Content-Length` is
    /// reached comes back as a read error, not as the end of the stream. The byte count
    /// kept here is a backstop behind that, so the guarantee belongs to this type rather
    /// than being inherited from whatever hyper does today - if the end of a stream is
    /// ever reported after fewer bytes than the storage promised, it is refused here
    /// instead of being passed off as a complete object.
    ///
    /// An object whose size was never stated (`content_length` is `None` - a chunked
    /// answer) has nothing to check against, so a truncation there rests on the
    /// transport alone.
    pub async fn get_next_chunk(&mut self) -> Result<Option<Vec<u8>>, S3Error> {
        let Some(chunk) = self.stream.get_next_chunk().await? else {
            if let Some(expected) = self.content_length
                && self.received < expected
            {
                return Err(S3Error::Other(format!(
                    "Download ended after {} of the {} bytes the storage said the object has",
                    self.received, expected
                )));
            }

            return Ok(None);
        };

        self.received += chunk.len() as u64;

        Ok(Some(chunk))
    }

    /// How many bytes have been handed out so far.
    pub fn received(&self) -> u64 {
        self.received
    }
}

/// Written by hand because the body it wraps has no `Debug` of its own - and because
/// there is nothing useful it could print anyway: the body is still on the socket, and
/// the point of this type is never to hold it.
impl std::fmt::Debug for S3DownloadStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3DownloadStream")
            .field("content_length", &self.content_length)
            .field("content_type", &self.content_type)
            .field("received", &self.received)
            .finish_non_exhaustive()
    }
}
