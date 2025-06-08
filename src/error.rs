use flurl::FlUrlError;

#[derive(Debug)]
pub enum S3Error {
    FlUrlError(FlUrlError),
    Other(String),
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
