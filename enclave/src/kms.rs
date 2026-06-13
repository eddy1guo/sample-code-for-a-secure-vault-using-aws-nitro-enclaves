// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! KMS and root-secret integration module for the Nitro Enclave.
//!
//! Root secret generation/injection still uses AWS KMS. Business payloads that
//! were previously wrapped directly by KMS are now encrypted in-memory with the
//! injected root secret. Legacy KMS ciphertexts remain decryptable for
//! compatibility with existing stored data and examples.

use std::sync::{LazyLock, RwLock};

use anyhow::{Result, anyhow, bail};
use openssl::symm::{Cipher, Crypter, Mode};
use rand::{RngCore, rngs::OsRng};
use rustls::crypto::hpke::HpkePrivateKey;
use zeroize::Zeroizing;

use crate::aws_ne;
use crate::codec::hex::{DecodeHex, EncodeHex};
use crate::credential::common::{TeeClient, Usage, WalletKeyBond};
use crate::models::{CreateWalletKeyRequest, Credential, EnclaveRequest};

pub const ROOT_SECRET_LEN_BYTES: usize = 32;
const ROOT_SECRET_NONCE_LEN_BYTES: usize = 12;
const ROOT_SECRET_TAG_LEN_BYTES: usize = 16;

static ROOT_SECRET: LazyLock<RwLock<Option<Zeroizing<Vec<u8>>>>> =
    LazyLock::new(|| RwLock::new(None));

/// A secure wrapper for HPKE private keys that zeroizes key material on drop.
pub struct SecureHpkePrivateKey {
    key_bytes: Zeroizing<Vec<u8>>,
}

impl SecureHpkePrivateKey {
    pub fn new(key_bytes: Vec<u8>) -> Self {
        Self {
            key_bytes: Zeroizing::new(key_bytes),
        }
    }

    pub fn as_hpke_private_key(&self) -> HpkePrivateKey {
        self.key_bytes.to_vec().into()
    }
}

fn kms_encrypt_biz_error() -> anyhow::Error {
    anyhow!(crate::error::Error::KMSEncryptFailed.to_json())
}

fn kms_decrypt_biz_error() -> anyhow::Error {
    anyhow!(crate::error::Error::KMSDecryptFailed.to_json())
}

fn root_secret_not_injected_error() -> anyhow::Error {
    anyhow!(crate::error::Error::RootSecretNotInjected.to_json())
}

fn root_secret_encrypt_biz_error() -> anyhow::Error {
    anyhow!(crate::error::Error::RootSecretEncryptFailed.to_json())
}

fn root_secret_decrypt_biz_error() -> anyhow::Error {
    anyhow!(crate::error::Error::RootSecretDecryptFailed.to_json())
}

fn kms_decrypt_raw(credential: &Credential, ciphertext: &str, region: &str) -> Result<Vec<u8>> {
    let ciphertext_bytes = ciphertext.decode_hex()?;

    aws_ne::kms_decrypt(
        region.as_bytes(),
        credential.access_key_id.as_bytes(),
        credential.secret_access_key.as_bytes(),
        credential.session_token.as_bytes(),
        &ciphertext_bytes,
    )
    .map_err(|e| anyhow!("KMS decrypt failed: {}", e))
}

fn call_kms_decrypt(credential: &Credential, ciphertext: &str, region: &str) -> Result<Vec<u8>> {
    kms_decrypt_raw(credential, ciphertext, region)
}

fn call_kms_encrypt(
    credential: &Credential,
    plaintext: &[u8],
    region: &str,
    key_id: &str,
) -> Result<Vec<u8>> {
    aws_ne::kms_encrypt(
        region.as_bytes(),
        credential.access_key_id.as_bytes(),
        credential.secret_access_key.as_bytes(),
        credential.session_token.as_bytes(),
        plaintext,
        key_id,
    )
    .map_err(|e| anyhow!("KMS encrypt failed: {}", e))
}

fn store_root_secret(root_secret: Zeroizing<Vec<u8>>) -> Result<()> {
    let mut root_secret_guard = ROOT_SECRET
        .write()
        .map_err(|_| anyhow!("root secret lock poisoned"))?;
    *root_secret_guard = Some(root_secret);
    Ok(())
}

fn cloned_root_secret() -> Result<Zeroizing<Vec<u8>>> {
    let root_secret_guard = ROOT_SECRET.read().map_err(|_| kms_decrypt_biz_error())?;
    let root_secret = root_secret_guard
        .as_ref()
        .ok_or_else(root_secret_not_injected_error)?;
    Ok(Zeroizing::new(root_secret.to_vec()))
}

pub fn encrypt_with_root_secret(plaintext: &str) -> Result<String> {
    let root_secret = cloned_root_secret()?;
    let mut nonce = [0u8; ROOT_SECRET_NONCE_LEN_BYTES];
    OsRng.fill_bytes(&mut nonce);

    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, root_secret.as_slice(), Some(&nonce))
        .map_err(|_| root_secret_encrypt_biz_error())?;
    crypter.pad(false);

    let mut ciphertext = vec![0u8; plaintext.len() + cipher.block_size()];
    let mut count = crypter
        .update(plaintext.as_bytes(), &mut ciphertext)
        .map_err(|_| root_secret_encrypt_biz_error())?;
    count += crypter
        .finalize(&mut ciphertext[count..])
        .map_err(|_| root_secret_encrypt_biz_error())?;
    ciphertext.truncate(count);

    let mut tag = [0u8; ROOT_SECRET_TAG_LEN_BYTES];
    crypter
        .get_tag(&mut tag)
        .map_err(|_| root_secret_encrypt_biz_error())?;

    let mut payload = Vec::with_capacity(
        ROOT_SECRET_NONCE_LEN_BYTES + ciphertext.len() + ROOT_SECRET_TAG_LEN_BYTES,
    );
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&tag);

    Ok(payload.encode_hex())
}

pub fn decrypt_with_root_secret(ciphertext: &str) -> Result<Vec<u8>> {
    let payload = ciphertext
        .decode_hex()
        .map_err(|_| root_secret_decrypt_biz_error())?;

    if payload.len() < ROOT_SECRET_NONCE_LEN_BYTES + ROOT_SECRET_TAG_LEN_BYTES {
        Err(root_secret_decrypt_biz_error())?;
    }

    let (nonce, ciphertext_and_tag) = payload.split_at(ROOT_SECRET_NONCE_LEN_BYTES);
    let split_at = ciphertext_and_tag
        .len()
        .checked_sub(ROOT_SECRET_TAG_LEN_BYTES)
        .ok_or_else(root_secret_decrypt_biz_error)?;
    let (encrypted, tag) = ciphertext_and_tag.split_at(split_at);

    let root_secret = cloned_root_secret()?;
    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, root_secret.as_slice(), Some(nonce))
        .map_err(|_| root_secret_decrypt_biz_error())?;
    crypter.pad(false);
    crypter
        .set_tag(tag)
        .map_err(|_| root_secret_decrypt_biz_error())?;

    let mut plaintext = vec![0u8; encrypted.len() + cipher.block_size()];
    let mut count = crypter
        .update(encrypted, &mut plaintext)
        .map_err(|_| root_secret_decrypt_biz_error())?;
    count += crypter
        .finalize(&mut plaintext[count..])
        .map_err(|_| root_secret_decrypt_biz_error())?;
    plaintext.truncate(count);

    Ok(plaintext)
}

pub fn generate_root_secret_ciphertext(
    credential: &Credential,
    region: &str,
    key_id: &str,
) -> Result<String> {
    let mut root_secret = Zeroizing::new(vec![0u8; ROOT_SECRET_LEN_BYTES]);
    OsRng.fill_bytes(root_secret.as_mut_slice());

    let ciphertext = call_kms_encrypt(credential, root_secret.as_slice(), region, key_id)?;
    Ok(ciphertext.encode_hex())
}

pub fn inject_root_secret_ciphertext(
    credential: &Credential,
    root_secret_ciphertext: &str,
    region: &str,
) -> Result<()> {
    let root_secret = Zeroizing::new(call_kms_decrypt(
        credential,
        root_secret_ciphertext,
        region,
    )?);

    if root_secret.len() != ROOT_SECRET_LEN_BYTES {
        bail!(
            "root secret length {} does not match expected {}",
            root_secret.len(),
            ROOT_SECRET_LEN_BYTES
        );
    }

    store_root_secret(root_secret)
}

pub fn root_secret_loaded() -> Result<bool> {
    let root_secret_guard = ROOT_SECRET
        .read()
        .map_err(|_| anyhow!("root secret lock poisoned"))?;
    Ok(root_secret_guard.is_some())
}

pub fn get_tee_client(
    _payload: &EnclaveRequest<CreateWalletKeyRequest>,
    device_ciphertext: &str,
) -> Result<TeeClient> {
    println!("{}:{}", file!(), line!());
    let plaintext = decrypt_with_root_secret(device_ciphertext)
        .map_err(|_| anyhow!(crate::error::Error::TeeClientCiphertextInvalid.to_json()))?;

    let client: TeeClient = serde_json::from_slice(&plaintext)?;
    if client.usage != Usage::RegisterTeeDevice {
        bail!(crate::error::Error::TeeClientUsageMismatch.to_json());
    }
    println!(
        "[enclave:plaintext_pubkey] decrypted tee client payload: {:?}",
        client
    );

    Ok(client)
}

use crate::model::RecoverWalletRequest;

pub fn get_tee_client2(payload: &EnclaveRequest<RecoverWalletRequest>) -> Result<TeeClient> {
    println!("{}:{}", file!(), line!());
    let plaintext = decrypt_with_root_secret(&payload.request.new_device_ciphertext)
        .map_err(|_| anyhow!(crate::error::Error::TeeClientCiphertextInvalid.to_json()))?;

    let client: TeeClient = serde_json::from_slice(&plaintext)?;
    if client.usage != Usage::RegisterTeeDevice {
        bail!(crate::error::Error::TeeClientUsageMismatch.to_json());
    }
    println!(
        "[enclave:plaintext_pubkey] decrypted tee client payload: {:?}",
        client
    );

    Ok(client)
}

pub fn get_wallet_key_bond(
    _credential: &Credential,
    ciphertext: &str,
    _region: &str,
) -> Result<WalletKeyBond> {
    println!("{}:{}", file!(), line!());
    let plaintext = decrypt_with_root_secret(ciphertext)
        .map_err(|_| anyhow!(crate::error::Error::WalletKeyBondCiphertextInvalid.to_json()))?;

    let client: WalletKeyBond = serde_json::from_slice(&plaintext)?;
    if client.usage != Usage::CreateWalletKey {
        bail!(crate::error::Error::WalletKeyBondUsageMismatch.to_json());
    }
    println!(
        "[enclave:plaintext_pubkey] decrypted wallet key bond payload: {:?}",
        client
    );

    Ok(client)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::credential::common::Platform;
    use crate::models::Credential;

    fn root_secret_bytes() -> Vec<u8> {
        vec![7u8; ROOT_SECRET_LEN_BYTES]
    }

    fn dummy_credential() -> Credential {
        Credential {
            access_key_id: "akid".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: "token".to_string(),
        }
    }

    fn clear_root_secret() {
        let mut root_secret_guard = ROOT_SECRET.write().unwrap();
        *root_secret_guard = None;
    }

    #[test]
    fn test_store_root_secret_marks_it_loaded() {
        clear_root_secret();

        store_root_secret(Zeroizing::new(root_secret_bytes())).unwrap();

        assert!(root_secret_loaded().unwrap());
    }

    #[test]
    fn test_store_root_secret_allows_overwrite() {
        clear_root_secret();

        store_root_secret(Zeroizing::new(root_secret_bytes())).unwrap();
        store_root_secret(Zeroizing::new(vec![9u8; ROOT_SECRET_LEN_BYTES])).unwrap();

        assert!(root_secret_loaded().unwrap());
    }

    #[test]
    fn test_business_payload_round_trip_uses_root_secret_prefix() {
        clear_root_secret();
        store_root_secret(Zeroizing::new(root_secret_bytes())).unwrap();

        let ciphertext = encrypt_with_root_secret("hello-root-secret").unwrap();
        let plaintext = decrypt_with_root_secret(&ciphertext).unwrap();
        assert_eq!(plaintext, b"hello-root-secret");
    }

    #[test]
    fn test_wallet_key_bond_round_trip_uses_root_secret_ciphertext() {
        clear_root_secret();
        store_root_secret(Zeroizing::new(root_secret_bytes())).unwrap();

        let bond = WalletKeyBond {
            user_id: 1,
            client_platform: Platform::Google,
            app_id: "app".to_string(),
            master_device_pubkey: "master".to_string(),
            tee_device_pubkey: "tee".to_string(),
            pwd_pubkey: "pwd".to_string(),
            wallet_prikey: "wallet".to_string(),
            usage: Usage::CreateWalletKey,
            counter: Some(1),
        };
        let plaintext = serde_json::to_string(&bond).unwrap();
        let ciphertext = encrypt_with_root_secret(&plaintext).unwrap();

        let decrypted =
            get_wallet_key_bond(&dummy_credential(), &ciphertext, "ap-southeast-1").unwrap();

        assert_eq!(decrypted.user_id, bond.user_id);
        assert_eq!(decrypted.master_device_pubkey, bond.master_device_pubkey);
        assert_eq!(decrypted.tee_device_pubkey, bond.tee_device_pubkey);
    }
}
