use std::borrow::Borrow;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Deserializer, de::DeserializeOwned, ser::Serialize};

pub trait JsonDeserialize: Borrow<str> {
    fn deserialize_json<T: DeserializeOwned>(&self) -> Result<T, anyhow::Error> {
        serde_json::from_str(self.borrow()).map_err(|e| {
            anyhow!(format!(
                "json decode failed: {},raw data: {}",
                e,
                self.borrow()
            ))
        })
    }
}
impl<T: Borrow<str>> JsonDeserialize for T {}

pub trait JsonSerialize: Serialize {
    fn serialize_json(&self) -> Result<String, anyhow::Error> {
        Ok(serde_json::to_string(&self)?)
    }
}
impl<T: Serialize> JsonSerialize for T {}

pub fn de_opt_str_or_num<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde_json::Value;

    let v = Value::deserialize(deserializer)?;

    match v {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(s)),
        Value::Number(n) => Ok(Some(n.to_string())),
        _ => Err(serde::de::Error::custom(
            "deviceOSVersion must be string or number",
        )),
    }
}
