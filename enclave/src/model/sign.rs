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
use crate::model::{Ed25519Title, EnclaveRequest, validate_nonce_issued_at};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub key_bond_ciphertext: String,
    pub key_bond_confirmed_assertion: String,
    pub pwd_sig: String,
    pub sign_assertion: String,
    pub message: String,
    pub issued_at: i64,
    pub nonce: String,
    pub region: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub sig: String,
}
impl EnclaveRequest<Request> {
    pub fn sign_payload(&self) -> String {
        #[derive(Serialize)]
        struct Payload {
            r#type: Usage,
            message: String,
            issued_at: i64,
            nonce: String,
        }
        let payload = Payload {
            r#type: Usage::Sign,
            message: self.request.message.clone(),
            issued_at: self.request.issued_at,
            nonce: self.request.nonce.clone(),
        };

        serde_json::to_string(&payload).unwrap()
    }

    pub fn confirm_payload(&self) -> String {
        #[derive(Serialize)]
        struct Payload {
            r#type: Usage,
            message: String,
        }
        let payload = Payload {
            r#type: Usage::ConfirmWalletKey,
            message: self.request.key_bond_ciphertext.clone(),
        };

        serde_json::to_string(&payload).unwrap()
    }

    pub fn validate(&self) -> Result<()> {
        if self.request.key_bond_ciphertext.is_empty() {
            println!("vault_id cannot be empty");
            Err(anyhow!(super::super::error::Error::ParamsInvalid.to_json()))?;
        }

        if self.request.sign_assertion.is_empty() {
            println!("in product mode,signature can't be none");
            Err(anyhow!(super::super::error::Error::ParamsInvalid.to_json()))?;
        }

        if self.request.message.is_empty() {
            println!("region cannot be empty");
            Err(anyhow!(super::super::error::Error::ParamsInvalid.to_json()))?;
        }

        if self.request.issued_at == 0 {
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

    pub fn execute(&self) -> Result<Response> {
        println!("request_data={:#?}", self.request);
        self.validate()?;
        println!("file={},line={}", file!(), line!());

        tokio::runtime::Runtime::new()?.block_on(validate_nonce_issued_at(
            &self.request.nonce,
            self.request.issued_at,
        ))?;

        let wallet_bond = get_wallet_key_bond(
            &self.credential,
            &self.request.key_bond_ciphertext,
            &self.request.region,
        )?;
        println!("file={},line={}", file!(), line!());

        //验证密码签名
        super::verify_pwd_sig(
            &self.sign_payload(),
            &wallet_bond.pwd_pubkey,
            &self.request.pwd_sig,
        )?;

        println!("file={},line={}", file!(), line!());

        //对key_bond_confirmed_assertion的校验
        let _counter = verify_assertion(
            wallet_bond.client_platform.clone(),
            &wallet_bond.app_id,
            &self.request.key_bond_confirmed_assertion,
            &wallet_bond.master_device_pubkey,
            &self.confirm_payload(),
        )?;
        println!("file={},line={}", file!(), line!());

        // assertion校验
        verify_assertion(
            wallet_bond.client_platform,
            &wallet_bond.app_id,
            &self.request.sign_assertion,
            &wallet_bond.tee_device_pubkey,
            &self.sign_payload(),
        )?;

        let wallet_prikey_bytes = wallet_bond
            .wallet_prikey
            .remove_title()
            .decode_bs58()
            .map_err(|e| {
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
        let sig = ed25519::sign(&wallet_prikey_bytes, &msg_bytes)?.encode_bs58();
        Ok(Response { sig })
    }
}
