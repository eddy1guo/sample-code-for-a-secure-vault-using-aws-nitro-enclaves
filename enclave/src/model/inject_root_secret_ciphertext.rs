use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::kms::inject_root_secret_ciphertext;
use crate::model::EnclaveRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub root_secret_ciphertext: String,
    pub region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub injected: bool,
}

impl EnclaveRequest<Request> {
    pub fn validate(&self) -> Result<()> {
        if self.request.root_secret_ciphertext.is_empty()
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

        inject_root_secret_ciphertext(
            &self.credential,
            &self.request.root_secret_ciphertext,
            &self.request.region,
        )?;

        Ok(Response { injected: true })
    }
}
