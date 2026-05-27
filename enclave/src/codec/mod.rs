pub mod bs58;
pub mod bs64;
pub mod hex;
pub mod json;

use anyhow::anyhow;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::codec::bs64::{DecodeBs64, EncodeBs64};
use crate::codec::hex::{DecodeHex, EncodeHex};
use crate::codec::json::{JsonDeserialize, JsonSerialize};

pub trait Encode {
    fn encode(&self) -> Result<String, anyhow::Error>;
}

pub trait Decode {
    fn decode<T: DeserializeOwned>(&self) -> Result<T, anyhow::Error>;
}
