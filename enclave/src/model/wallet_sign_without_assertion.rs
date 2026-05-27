use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::codec::bs58::{DecodeBs58, EncodeBs58};
use crate::codec::bs64::DecodeBs64;
use crate::credential::assertion::verify_assertion;
use crate::credential::aws::is_debug_mode;
use crate::credential::common::Usage;
use crate::ed25519;
use crate::kms::get_wallet_key_bond;
use crate::model::{DecryptRequire, EnclaveRequest, validate_nonce_issue_at};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub key_bond_ciphertext: String,
    pub key_bond_confirmed_assertion: String,
    pub pwd_sig: String,
    pub message: String,
    pub issue_at: i64,
    pub nonce: String,
    pub region: String,
}

impl DecryptRequire for Request {
    fn ciphertext(&self) -> &String {
        &self.key_bond_ciphertext
    }

    fn region(&self) -> &String {
        &self.region
    }
}

impl EnclaveRequest<Request> {
    pub fn sign_payload(&self) -> String {
        json!({
            "type": Usage::WalletSign,
            "message": self.request.message,
            "issued_at": self.request.issue_at,
            "nonce": self.request.nonce,
        })
        .to_string()
    }

    pub fn validate(&self) -> Result<()> {
        if self.request.key_bond_ciphertext.is_empty() {
            println!("vault_id cannot be empty");
            Err(anyhow!(super::super::error::Error::ParamsInvalid.to_json()))?;
        }

        if self.request.message.is_empty() {
            println!("region cannot be empty");
            Err(anyhow!(super::super::error::Error::ParamsInvalid.to_json()))?;
        }

        if self.request.issue_at == 0 {
            println!("region cannot be empty");
            Err(anyhow!(super::super::error::Error::ParamsInvalid.to_json()))?;
        }

        if self.request.nonce.is_empty() {
            println!("region cannot be empty");
            Err(anyhow!(super::super::error::Error::ParamsInvalid.to_json()))?;
        }

        if !self
            .request
            .region
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            println!("region contains invalid characters");
            Err(anyhow!(super::super::error::Error::ParamsInvalid.to_json()))?;
        }

        Ok(())
    }

    pub fn sign(&self) -> Result<String> {
        self.validate()?;

        tokio::runtime::Runtime::new()?.block_on(validate_nonce_issue_at(
            &self.request.nonce,
            self.request.issue_at,
        ))?;

        let wallet_bond = get_wallet_key_bond(
            &self.credential,
            &self.request.key_bond_ciphertext,
            &self.request.region,
        )?;

        if is_debug_mode()? {
            println!("skip verification for debug mode");
        } else {
            //todo: 针对无硬件assertion的业务，需要增加强制帐号锁定的机制
        }

        let wallet_prikey_bytes = wallet_bond.wallet_prikey.decode_bs58().map_err(|e| {
            println!("{:?}", e);
            anyhow!(super::super::error::Error::ParamsInvalid.to_json())
        })?;
        println!(
            "[enclave] decrypted KMS secret key {}",
            wallet_prikey_bytes.encode_bs58()
        );

        let msg_bytes = self.request.message.decode_bs64().map_err(|e| {
            println!("{:?}", e);
            anyhow!(super::super::error::Error::ParamsInvalid.to_json())
        })?;
        let sig = ed25519::sign(&wallet_prikey_bytes, &msg_bytes)?;
        Ok(sig.encode_bs58())
    }
}
