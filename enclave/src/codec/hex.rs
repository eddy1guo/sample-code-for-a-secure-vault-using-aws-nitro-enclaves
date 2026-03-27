use std::borrow::Borrow;

pub use anyhow::Result;
use hex::ToHex;

pub trait EncodeHex: AsRef<[u8]> {
    fn encode_hex(&self) -> String {
        ToHex::encode_hex(&self.as_ref())
    }
}
impl<T: AsRef<[u8]>> EncodeHex for T {}

pub trait DecodeHex: Borrow<str> {
    fn decode_hex(&self) -> Result<Vec<u8>> {
        Ok(hex::decode(self.borrow())?)
    }
}
impl<T: Borrow<str>> DecodeHex for T {}
