use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::codec::json::JsonSerialize;
use crate::credential::attestation::verify_attestation;
use crate::credential::common::{Platform, TeeClient, Usage};
use crate::kms::encrypt_with_root_secret;
use crate::model::{DecryptRequire, EnclaveRequest, validate_nonce_issued_at};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub platform: Platform,
    pub attestation: Vec<String>,
    pub issued_at: i64,
    pub nonce: String,
    pub key_id: String,
    pub region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub client_ciphertext: String,
    pub tee_device_pubkey: String,
}

impl EnclaveRequest<Request> {
    pub fn sign_payload(&self) -> String {
        #[derive(Serialize)]
        struct Payload {
            r#type: Usage,
            issued_at: i64,
            nonce: String,
        }
        let payload = Payload {
            r#type: Usage::RegisterTeeDevice,
            issued_at: self.request.issued_at,
            nonce: self.request.nonce.clone(),
        };

        serde_json::to_string(&payload).unwrap()
    }
    pub fn validate(&self) -> Result<()> {
        if self.request.issued_at == 0 {
            println!("region cannot be empty");
            Err(anyhow!(super::super::error::Error::ParamsInvalid.to_json()))?;
        }

        if self.request.nonce.is_empty() {
            println!("region cannot be empty");
            Err(anyhow!(super::super::error::Error::ParamsInvalid.to_json()))?;
        }
        Ok(())
    }

    pub fn execute(&self) -> Result<Response> {
        println!("request_data={:#?}", self.request);
        tokio::runtime::Runtime::new()?.block_on(validate_nonce_issued_at(
            &self.request.nonce,
            self.request.issued_at,
        ))?;
        println!("file={},line={}", file!(), line!());
        //let attestation = self.attestation()?;
        let (app_id, pubkey) = verify_attestation(
            &self.request.platform,
            self.sign_payload().as_bytes(),
            &self.request.attestation,
        )?;
        let tee_client = TeeClient {
            platform: self.request.platform.clone(),
            pubkey: pubkey.clone(),
            app_id,
            usage: Usage::RegisterTeeDevice,
        }
        .serialize_json()?;
        println!("file={},line={}", file!(), line!());
        let client_ciphertext = encrypt_with_root_secret(&tee_client)
            .map_err(|err| anyhow!("failed to encrypt with root secret: {err:?}"))?;
        Ok(Response {
            client_ciphertext,
            tee_device_pubkey: pubkey,
        })
    }
}
