use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::kms::generate_root_secret_ciphertext;
use crate::model::EnclaveRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub key_id: String,
    pub region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub root_secret_ciphertext: String,
}

impl EnclaveRequest<Request> {
    pub fn validate(&self) -> Result<()> {
        if self.request.key_id.is_empty()
            || self.request.region.is_empty()
            || !self
                .request
                .region
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            Err(anyhow!(crate::error::Error::ParamsInvalid.to_json()))?;
        }

        Ok(())
    }

    pub fn execute(&self) -> Result<Response> {
        self.validate()?;

        let root_secret_ciphertext = generate_root_secret_ciphertext(
            &self.credential,
            &self.request.region,
            &self.request.key_id,
        )?;

        Ok(Response {
            root_secret_ciphertext,
        })
    }
}
