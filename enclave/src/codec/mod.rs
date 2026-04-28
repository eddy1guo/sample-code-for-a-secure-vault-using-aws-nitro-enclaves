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

pub fn serialize_as_bs64_json<T: Serialize>(value: &T) -> Result<String, anyhow::Error> {
    let json = value.serialize_json()?;
    Ok(json.as_bytes().encode_bs64())
}

pub fn deserialize_from_bs64_json<T: DeserializeOwned>(value: &str) -> Result<T, anyhow::Error> {
    let bytes = value.decode_bs64()?;
    let json = String::from_utf8(bytes).map_err(|err| anyhow!("utf8 decode failed: {err}"))?;
    json.deserialize_json()
}
