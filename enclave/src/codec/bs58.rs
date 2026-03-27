use std::borrow::Borrow;

pub use anyhow::Result;
pub use bs58;

// pub fn encode<I: AsRef<[u8]>>(input: &I) -> String {
//     bs58::encode(input.as_ref()).into_string()
// }
// pub fn decode<I: Borrow<str>>(input: &I) -> Result<Vec<u8>> {
//     Ok(bs58::decode(input.borrow().as_bytes()).into_vec()?)
// }

pub trait EncodeBs58: AsRef<[u8]> {
    fn encode_bs58(&self) -> String {
        bs58::encode(self.as_ref()).into_string()
    }
}

impl<T: AsRef<[u8]>> EncodeBs58 for T {}

pub trait DecodeBs58: Borrow<str> {
    fn decode_bs58(&self) -> Result<Vec<u8>> {
        Ok(bs58::decode(self.borrow().as_bytes()).into_vec()?)
    }
}

impl<T: Borrow<str>> DecodeBs58 for T {}
