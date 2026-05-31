use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::codec::bs58::{DecodeBs58, EncodeBs58};
use crate::codec::hex::EncodeHex;
use crate::codec::json::JsonSerialize;
use crate::credential::assertion::verify_assertion;
use crate::credential::aws::is_debug_mode;
use crate::credential::common::{Usage, WalletKeyBond};
use crate::ed25519::{self, new_key_pair};
use crate::error::Error;
use crate::kms::{call_kms_encrypt, get_tee_client};
use crate::model::{DecryptRequire, EnclaveRequest, validate_nonce_issued_at};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub device_ciphertext: String,
    pub device_confirmed_assertion: String,
    pub bind_device_ciphertext: String,
    pub bind_device_confirmed_assertion: String,
    pub pwd_pubkey: String,
    pub pwd_sig: String,
    pub create_key_assertion: String,
    pub issued_at: i64,
    pub nonce: String,
    pub key_id: String,
    pub region: String,
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
            r#type: Usage::CreateWalletKey,
            issued_at: self.request.issued_at,
            nonce: self.request.nonce.clone(),
        };

        serde_json::to_string(&payload).unwrap()
    }

    pub fn confirm_payload(&self, ciphertext: &str) -> String {
        #[derive(Serialize)]
        struct Payload {
            r#type: Usage,
            message: String,
        }
        let payload = Payload {
            r#type: Usage::ConfirmTeeDevice,
            message: ciphertext.to_owned(),
        };

        serde_json::to_string(&payload).unwrap()
    }

    pub fn validate(&self) -> Result<()> {
        if self.request.issued_at == 0 {
            println!("issued_at cannot be empty");
            Err(anyhow!(super::super::error::Error::ParamsInvalid.to_json()))?;
        }

        if self.request.nonce.is_empty() {
            println!("region cannot be empty");
            Err(anyhow!(super::super::error::Error::ParamsInvalid.to_json()))?;
        }
        Ok(())
    }

    fn encrypt(&self, plaint_text: &str) -> Result<Vec<u8>> {
        call_kms_encrypt(
            &self.credential,
            plaint_text,
            &self.request.region,
            &self.request.key_id,
        )
        .map_err(|err| anyhow!("failed to call KMS:call_kms_encrypt: {err:?}"))
    }

    pub fn execute(&self) -> Result<(String, String)> {
        tokio::runtime::Runtime::new()?.block_on(validate_nonce_issued_at(
            &self.request.nonce,
            self.request.issued_at,
        ))?;
        //验证密码签名
        super::verify_pwd_sig(
            &self.sign_payload(),
            &self.request.pwd_pubkey,
            &self.request.pwd_sig,
        )?;
        println!("file={},line={}", file!(), line!());

        //获取当前的设备证明
        let client = get_tee_client(&self, &self.request.device_ciphertext)?;
        //先验证当前客户端的assertion
        let _counter = verify_assertion(
            client.platform.clone(),
            &client.app_id,
            &self.request.device_confirmed_assertion,
            &client.pubkey,
            &self.confirm_payload(&self.request.device_ciphertext),
        )?;
        println!("file={},line={}", file!(), line!());

        //验证被绑定客户端的assertion
        let bind_client = get_tee_client(&self, &self.request.bind_device_ciphertext)?;
        //先验证客户端对kms加密结果的认证
        let _counter = verify_assertion(
            bind_client.platform.clone(),
            &bind_client.app_id,
            &self.request.bind_device_confirmed_assertion,
            &bind_client.pubkey,
            &self.confirm_payload(&self.request.bind_device_ciphertext),
        )?;

        println!("file={},line={}", file!(), line!());
        //验证客户端对本次创建tee-key的签名
        let counter = verify_assertion(
            client.platform.clone(),
            &client.app_id,
            &self.request.create_key_assertion,
            &client.pubkey,
            &self.sign_payload(),
        )?;
        println!("file={},line={}", file!(), line!());
        let key_pair = new_key_pair();
        let wallet_prikey = key_pair.0.encode_bs58();
        let wallet_pubkey = key_pair.1.encode_bs58();
        let plaint_text = WalletKeyBond {
            client_platform: client.platform,
            master_device_pubkey: client.pubkey,
            tee_device_pubkey: bind_client.pubkey,
            pwd_pubkey: self.request.pwd_pubkey.clone(),
            wallet_prikey: wallet_prikey.clone(),
            usage: Usage::CreateWalletKey,
            app_id: client.app_id,
            counter,
        }
        .serialize_json()?;
        println!("generate new wallet:  {} ", plaint_text);
        Ok((self.encrypt(&plaint_text)?.encode_hex(), wallet_pubkey))
    }
}
