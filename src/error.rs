use flurl::FlUrlError;

#[derive(Debug)]
pub enum S3Error {
    FlUrlError(FlUrlError),
    /// `BucketAlreadyExists` - the name is taken by *somebody else*. Retrying never helps.
    BucketAlreadyExists,
    /// `BucketAlreadyOwnedByYou` - the bucket is already ours. This is what S3 answers
    /// on every re-`create_bucket` after the first one, so a service that ensures its
    /// bucket on startup sees this on every restart. Treat it as success.
    BucketAlreadyOwnedByYou,
    /// `NoSuchBucket`.
    BucketNotFound,
    /// `NoSuchKey` - the object is not there. Distinct from a transport/permission
    /// failure, so callers can map "no data" to an empty result instead of an error.
    KeyNotFound,
    /// `NoSuchUpload` - the multipart upload id is unknown or already
    /// completed/aborted.
    NoSuchUpload,
    /// `EntityTooSmall` - a multipart part other than the last one was under the 5 MiB
    /// minimum S3 enforces.
    EntityTooSmall,
    RangeNotSatisfiable,
    /// A non-2xx answer that did not map to any variant above.
    ///
    /// The status code is kept as a number, not folded into a message: deciding whether
    /// to retry needs `>= 500` and `== 429`, and parsing that back out of a rendered
    /// string is how a caller ends up matching on `"Status Code: 204"`.
    UnexpectedStatusCode {
        status_code: u16,
        /// `<Error><Code>` from the body, when the body was XML at all.
        error_code: Option<String>,
        body: String,
    },
    /// The producer handed to [`crate::S3Client::upload_with_writer`] failed before it
    /// had written the whole body.
    ///
    /// This is the *source's* failure, not the storage's - a file that could not be
    /// read, a serializer that gave up - and it is reported in preference to the S3
    /// error it causes, which is only ever "the body was shorter than `Content-Length`"
    /// and says nothing about why.
    UploadProducerFailed(std::io::Error),
    Other(String),
}

impl S3Error {
    pub fn is_bucket_already_exists(&self) -> bool {
        matches!(self, Self::BucketAlreadyExists)
    }

    pub fn is_bucket_already_owned_by_you(&self) -> bool {
        matches!(self, Self::BucketAlreadyOwnedByYou)
    }

    /// True for both "the name is taken" cases. Useful for the ensure-bucket-on-startup
    /// pattern, where either outcome means "stop trying to create it".
    pub fn bucket_name_is_taken(&self) -> bool {
        matches!(
            self,
            Self::BucketAlreadyExists | Self::BucketAlreadyOwnedByYou
        )
    }

    pub fn is_bucket_not_found(&self) -> bool {
        matches!(self, Self::BucketNotFound)
    }

    pub fn is_key_not_found(&self) -> bool {
        matches!(self, Self::KeyNotFound)
    }

    pub fn is_no_such_upload(&self) -> bool {
        matches!(self, Self::NoSuchUpload)
    }

    pub fn is_entity_too_small(&self) -> bool {
        matches!(self, Self::EntityTooSmall)
    }

    pub fn is_range_not_satisfiable(&self) -> bool {
        matches!(self, Self::RangeNotSatisfiable)
    }

    pub fn is_upload_producer_failed(&self) -> bool {
        matches!(self, Self::UploadProducerFailed(_))
    }

    /// The producer's own `io::Error`, for a caller that wants to match on its
    /// [`std::io::ErrorKind`] - `InvalidInput` for a body that ran past
    /// `Content-Length`, `UnexpectedEof` for one that stopped short.
    pub fn get_upload_producer_error(&self) -> Option<&std::io::Error> {
        match self {
            Self::UploadProducerFailed(err) => Some(err),
            _ => None,
        }
    }

    pub fn get_status_code(&self) -> Option<u16> {
        match self {
            Self::UnexpectedStatusCode { status_code, .. } => Some(*status_code),
            _ => None,
        }
    }

    /// Whether repeating the very same request could plausibly succeed.
    ///
    /// This exists because a streamed upload is attempted **exactly once**:
    /// `FlUrl::with_retries` is ignored for a streamed body (the payload is consumed as
    /// it is sent), so retrying is the caller's decision and it needs something better
    /// than a string to base it on.
    ///
    /// Retrying an upload is safe despite not being retried automatically: `PutObject`
    /// replaces the whole object and is atomic, so a failed attempt leaves either the
    /// previous object or nothing - never a half-written one. What the caller must
    /// rebuild is the *payload*, from the beginning.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::FlUrlError(err) => fl_url_error_is_retryable(err),

            Self::UnexpectedStatusCode {
                status_code,
                error_code,
                ..
            } => {
                // S3 asks for a retry by name in these, whatever the status happens
                // to be.
                if let Some(error_code) = error_code
                    && matches!(
                        error_code.as_str(),
                        "SlowDown"
                            | "RequestTimeout"
                            | "RequestTimeTooSkewed"
                            | "InternalError"
                            | "ServiceUnavailable"
                    )
                {
                    return true;
                }

                // 5xx is the server's problem, not the request's; 429 is explicit
                // backpressure. Every other 4xx is deterministic - repeating it
                // reproduces it.
                *status_code >= 500 || *status_code == 429
            }

            // Typed outcomes are all deterministic answers about the state of the
            // bucket, so a retry returns the same thing.
            Self::BucketAlreadyExists
            | Self::BucketAlreadyOwnedByYou
            | Self::BucketNotFound
            | Self::KeyNotFound
            | Self::NoSuchUpload
            | Self::EntityTooSmall
            | Self::RangeNotSatisfiable => false,

            // The body could not be produced. Repeating the request would ask the same
            // source for the same bytes and fail the same way; what has to change is
            // local, so the retry - if any - is the caller's to decide, not this
            // crate's to take automatically.
            Self::UploadProducerFailed(_) => false,

            Self::Other(_) => false,
        }
    }
}

/// Transport failures that say nothing about whether the request was acceptable - a
/// fresh connection may well work. Notably a *timeout* counts as retryable here, which
/// for a large upload usually means `upload_timeout` was too small rather than that the
/// network is broken; retrying without raising it will just time out again.
fn fl_url_error_is_retryable(err: &FlUrlError) -> bool {
    if err.is_timeout() || err.is_hyper_canceled() {
        return true;
    }

    match err {
        FlUrlError::IoError(_)
        | FlUrlError::CanNotEstablishConnection(_)
        | FlUrlError::InvalidHttp1HandShake(_)
        | FlUrlError::ReadingHyperBodyError(_)
        | FlUrlError::HyperError(_) => true,

        FlUrlError::MyHttpClientError(err) => err.is_retryable(),

        // Configuration and programming errors: a retry changes nothing. `FlUrlError`
        // is #[non_exhaustive], so unknown future variants land here too - defaulting
        // to "do not retry" keeps a new variant from turning into a hot loop.
        _ => false,
    }
}

impl std::fmt::Display for S3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FlUrlError(err) => write!(f, "FlUrl error: {:?}", err),
            Self::BucketAlreadyExists => write!(f, "BucketAlreadyExists"),
            Self::BucketAlreadyOwnedByYou => write!(f, "BucketAlreadyOwnedByYou"),
            Self::BucketNotFound => write!(f, "NoSuchBucket"),
            Self::KeyNotFound => write!(f, "NoSuchKey"),
            Self::NoSuchUpload => write!(f, "NoSuchUpload"),
            Self::EntityTooSmall => write!(f, "EntityTooSmall"),
            Self::RangeNotSatisfiable => write!(f, "RangeNotSatisfiable"),
            // Keeps the historical "Status Code: {n}. Err: {body}" shape, so callers
            // that still match on that substring keep working while they migrate to
            // `get_status_code()`.
            Self::UnexpectedStatusCode {
                status_code, body, ..
            } => write!(f, "Status Code: {}. Err: {}", status_code, body),
            Self::UploadProducerFailed(err) => {
                write!(f, "The upload body could not be produced: {}", err)
            }
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for S3Error {
    /// Only [`S3Error::UploadProducerFailed`] has one: the producer's `io::Error` is a
    /// real error of its own, often wrapping the caller's, and `?` in an
    /// `io::Error`-shaped caller should be able to walk back to it.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UploadProducerFailed(err) => Some(err),
            _ => None,
        }
    }
}

impl From<FlUrlError> for S3Error {
    fn from(value: FlUrlError) -> Self {
        Self::FlUrlError(value)
    }
}

impl From<String> for S3Error {
    fn from(value: String) -> Self {
        Self::Other(value)
    }
}

impl From<&'_ str> for S3Error {
    fn from(value: &str) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<&'_ String> for S3Error {
    fn from(value: &String) -> Self {
        Self::Other(value.to_string())
    }
}
