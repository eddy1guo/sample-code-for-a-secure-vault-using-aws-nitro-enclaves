use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::codec::bs58::{DecodeBs58, EncodeBs58};
use crate::codec::bs64::DecodeBs64;
use crate::codec::hex::EncodeHex;
use crate::codec::json::JsonSerialize;
use crate::credential::assertion::verify_assertion;
use crate::credential::aws::is_debug_mode;
use crate::credential::common::Usage;
use crate::ed25519::{self, ExtractPubkey};
use crate::functions::now_millis;
use crate::kms::{call_kms_encrypt, get_tee_client, get_tee_client2, get_wallet_key_bond};
use crate::model::{
    ConfirmedKeyBond, DecryptRequire, Ed25519Title, EnclaveRequest, validate_nonce_issued_at,
};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub new_device_ciphertext: String,
    pub new_device_confirmed_assertion: String,
    pub key_bonds: Vec<ConfirmedKeyBond>,
    pub pwd_sig: String,
    pub assertion: String,
    pub issued_at: i64,
    pub nonce: String,
    pub key_id: String,
    pub region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBondMap {
    pub key_bond_ciphertext: String,
    pub wallet_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub new_key_bonds: Vec<KeyBondMap>,
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
            r#type: Usage::RecoverWallet,
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
            r#type: Usage::ConfirmTeeDevice,
            message: self.request.new_device_ciphertext.clone(),
        };

        serde_json::to_string(&payload).unwrap()
    }

    pub fn validate(&self) -> Result<()> {
        if self.request.key_bonds.is_empty() {
            println!("vault_id cannot be empty");
            Err(anyhow!(super::super::error::Error::ParamsInvalid.to_json()))?;
        }

        if self.request.assertion.is_empty() {
            println!("in product mode,signature can't be none");
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

        tokio::runtime::Runtime::new()?.block_on(validate_nonce_issued_at(
            &self.request.nonce,
            self.request.issued_at,
        ))?;
        println!("file={},line={}", file!(), line!());

        let new_device = get_tee_client2(&self)?;

        //先验证新客户端对kms加密结果的认证
        let _counter = verify_assertion(
            new_device.platform.clone(),
            &new_device.app_id,
            &self.request.new_device_confirmed_assertion,
            &new_device.pubkey,
            &self.confirm_payload(),
        )?;
        println!("file={},line={}", file!(), line!());

        //这里仅为了提取pwd_pubkey，任何一个成员的都行
        let wallet_bond = get_wallet_key_bond(
            &self.credential,
            &self.request.key_bonds[0].ciphertext,
            &self.request.region,
        )?;

        //验证密码签名
        super::verify_pwd_sig_with_lock(
            &wallet_bond.app_id,
            &self.sign_payload(),
            &wallet_bond.pwd_pubkey,
            &self.request.pwd_sig,
        )?;

        // 当前recovery和modify_pwd的区别就是不再校验硬件证明
        // 且修改所有的key的主设备，因为recovery一定是只能恢复成主设备
        //todo: 后续会加上 帐号密码试错的锁定的机制
        // verify_assertion(
        //     wallet_bond.client_platform,
        //     &wallet_bond.app_id,
        //     &self.request.assertion,
        //     &wallet_bond.tee_device_pubkey,
        //     &self.sign_payload(),
        // )?;

        //校验每个key的客户端确认签名并且解密后换绑重新加密
        let mut new_key_bonds = vec![];
        println!("{},time={}", line!(), now_millis());
        for bond in self.request.key_bonds.iter() {
            println!("{},time={}", line!(), now_millis());
            let mut wallet_bond =
                get_wallet_key_bond(&self.credential, &bond.ciphertext, &self.request.region)?;
            println!("{},time={}", line!(), now_millis());

            verify_assertion(
                wallet_bond.client_platform.clone(),
                &wallet_bond.master_device_pubkey,
                &bond.confirmed_assertion,
                &wallet_bond.master_device_pubkey,
                &bond.confirm_payload(),
            )
            .map_err(|e| {
                println!("{:?}", e);
                anyhow!(crate::error::Error::AssertionVerifyFailed.to_json())
            })?;
            // 新设备作为所有旧设备的主设备
            wallet_bond.master_device_pubkey = new_device.pubkey.clone();
            // 对于旧的主设备还要更新自身key
            if wallet_bond.is_master() {
                wallet_bond.tee_device_pubkey = new_device.pubkey.clone();
            }
            let wallet_pubkey = wallet_bond.wallet_prikey.extract_pubkey()?.add_title();
            let plaint_text = wallet_bond.serialize_json()?;
            println!("{},time={}", line!(), now_millis());
            let key_bond_ciphertext = call_kms_encrypt(
                &self.credential,
                &plaint_text,
                &self.request.region,
                &self.request.key_id,
            )
            .map_err(|err| anyhow!("failed to call KMS:call_kms_encrypt: {err:?}"))?
            .encode_hex();
            println!("{},time={}", line!(), now_millis());
            //new_key_bonds.push((key_bond_ciphertext, wallet_pubkey))
            let key_bond = KeyBondMap {
                key_bond_ciphertext,
                wallet_pubkey,
            };
            new_key_bonds.push(key_bond)
        }
        println!("{},time={}", line!(), now_millis());
        Ok(Response { new_key_bonds })
    }
}
