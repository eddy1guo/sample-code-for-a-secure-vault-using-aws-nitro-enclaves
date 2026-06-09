use anyhow::{Result, anyhow, bail};
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
use crate::kms::get_wallet_key_bond;
use crate::kms::{call_kms_encrypt, get_tee_client};
use crate::model::{DecryptRequire, Ed25519Title, EnclaveRequest, validate_nonce_issued_at};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub user_id: u64,
    pub device_ciphertext: String,
    pub device_confirmed_assertion: String,
    pub bind_device_ciphertext: String,
    pub bind_device_confirmed_assertion: String,
    pub master_key_bond_ciphertext: Option<String>,
    pub master_key_bond_confirmed_assertion: Option<String>,
    pub pwd_pubkey: String,
    pub pwd_sig: String,
    pub create_key_assertion: String,
    pub issued_at: i64,
    pub nonce: String,
    pub key_id: String,
    pub region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub key_bond_ciphertext: String,
    pub wallet_pubkey: String,
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

    pub fn device_confirm_payload(&self, ciphertext: &str) -> String {
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

    pub fn master_key_bond_confirm_payload(&self, ciphertext: String) -> String {
        #[derive(Serialize)]
        struct Payload {
            r#type: Usage,
            message: String,
            issued_at: i64,
            nonce: String,
        }
        let payload = Payload {
            r#type: Usage::Sign,
            message: ciphertext,
            issued_at: self.request.issued_at,
            nonce: self.request.nonce.clone(),
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

    pub fn execute(&self) -> Result<Response> {
        println!("request_data={:#?}", self.request);
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

        //非强制行为，有应用层决定是否来和master的pwd_pubkey保持一致,这样体验更好，跳过也不影响安全
        match (
            &self.request.master_key_bond_ciphertext,
            &self.request.master_key_bond_confirmed_assertion,
        ) {
            (Some(ciphertext), Some(confirm_assertion)) => {
                let master_key_bond =
                    get_wallet_key_bond(&self.credential, &ciphertext, &self.request.region)?;
                verify_assertion(
                    master_key_bond.client_platform.clone(),
                    &master_key_bond.app_id,
                    &confirm_assertion,
                    &master_key_bond.master_device_pubkey,
                    &self.master_key_bond_confirm_payload(ciphertext.clone()),
                )?;
                if self.request.pwd_pubkey != master_key_bond.pwd_pubkey {
                    bail!(Error::PasswordDifferentWithMasterKey.to_json())
                }
            }
            _ => {}
        };

        //获取当前的设备证明
        let client = get_tee_client(&self, &self.request.device_ciphertext)?;
        //先验证当前客户端的assertion
        let _counter = verify_assertion(
            client.platform.clone(),
            &client.app_id,
            &self.request.device_confirmed_assertion,
            &client.pubkey,
            &self.device_confirm_payload(&self.request.device_ciphertext),
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
            &self.device_confirm_payload(&self.request.bind_device_ciphertext),
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
        let wallet_prikey = key_pair.0.encode_bs58().add_title();
        let wallet_pubkey = key_pair.1.encode_bs58().add_title();
        let plaint_text = WalletKeyBond {
            user_id: self.request.user_id,
            client_platform: client.platform,
            //create_key的几个场景（帐号注册、创建子帐号、为从设备创建key，新换主、从换主），该值都是主设备
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
        let res: Response = Response {
            key_bond_ciphertext: self.encrypt(&plaint_text)?.encode_hex(),
            wallet_pubkey,
        };
        Ok(res)
    }
}
