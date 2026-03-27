use std::borrow::Borrow;

pub use anyhow::Result;
pub use base64::{prelude::BASE64_STANDARD, Engine};

pub fn encode<I: AsRef<[u8]>>(input: &I) -> String {
    BASE64_STANDARD.encode(input.as_ref())
}
pub fn decode<I: Borrow<str>>(input: &I) -> Result<Vec<u8>> {
    Ok(BASE64_STANDARD.decode(input.borrow())?)
}

pub trait EncodeBs64: AsRef<[u8]> {
    fn encode_bs64(&self) -> String {
        BASE64_STANDARD.encode(self.as_ref())
    }
}

impl<T: AsRef<[u8]>> EncodeBs64 for T {}

pub trait DecodeBs64: Borrow<str> {
    fn decode_bs64(&self) -> Result<Vec<u8>> {
        Ok(BASE64_STANDARD.decode(self.borrow())?)
    }
}

impl<T: Borrow<str>> DecodeBs64 for T {}
