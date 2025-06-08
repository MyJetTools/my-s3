pub trait S3BodyReader {
    type Result;
    const HAS_BODY: bool;

    fn from_vec(src: Vec<u8>) -> Self::Result;

    fn default() -> Self::Result;
}

#[async_trait::async_trait]
impl S3BodyReader for () {
    type Result = ();
    const HAS_BODY: bool = false;

    fn from_vec(_src: Vec<u8>) -> Self::Result {
        ()
    }

    fn default() -> Self::Result {
        ()
    }
}

impl S3BodyReader for Vec<u8> {
    type Result = Vec<u8>;
    const HAS_BODY: bool = true;

    fn from_vec(src: Vec<u8>) -> Self::Result {
        src
    }

    fn default() -> Self::Result {
        vec![]
    }
}
