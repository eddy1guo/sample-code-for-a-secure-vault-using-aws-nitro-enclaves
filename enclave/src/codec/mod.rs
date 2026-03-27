pub mod bs58;
pub mod bs64;
pub mod hex;
pub mod json;

use serde::de::DeserializeOwned;

pub trait Encode {
    fn encode(&self) -> Result<String, anyhow::Error>;
}

pub trait Decode {
    fn decode<T: DeserializeOwned>(&self) -> Result<T, anyhow::Error>;
}

//serde
