// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! KMS integration module for the Nitro Enclave.
//!
//! This module provides functionality to decrypt KMS-encrypted private keys using
//! the AWS Nitro Enclaves SDK FFI wrapper. The decrypted private keys are used
//! for HPKE decryption of vault field values.
//!
//! # Security
//!
//! - Private key material is zeroized immediately after extraction
//! - KMS decryption is performed via the Nitro Enclaves SDK which uses
//!   attestation-based access control
//! - The KMS key policy must allow the enclave's PCR values to decrypt
//! - HPKE private keys are wrapped in [`SecureHpkePrivateKey`] which zeroizes on drop

use anyhow::{Result, anyhow, bail};
use aws_lc_rs::encoding::AsBigEndian;
use aws_lc_rs::signature::{EcdsaKeyPair, EcdsaSigningAlgorithm};
use rustls::crypto::hpke::HpkePrivateKey;
use zeroize::{Zeroize, Zeroizing};

use crate::aws_ne;
use crate::codec::bs58::{DecodeBs58, EncodeBs58};
use crate::codec::bs64::EncodeBs64;
use crate::codec::hex::DecodeHex;
use crate::codec::json::JsonDeserialize;
use crate::credential::common::{TeeClient, Usage, WalletKeyBond};
use crate::model::DecryptRequire;
use crate::models::{CreateWalletKeyRequest, Credential, EnclaveRequest};
use crate::utils::base64_decode;

/// A secure wrapper for HPKE private keys that zeroizes key material on drop.
///
/// This wrapper stores the raw key bytes in a [`Zeroizing`] container, ensuring
/// the key material is securely erased from memory when no longer needed.
///
/// # Security
///
/// - Key bytes are stored in a `Zeroizing<Vec<u8>>` which zeroizes on drop
/// - The `HpkePrivateKey` is created on-demand from the zeroized source
/// - This ensures our copy of the key material is always cleaned up
pub struct SecureHpkePrivateKey {
    /// The raw private key bytes, wrapped for automatic zeroization
    key_bytes: Zeroizing<Vec<u8>>,
}

impl SecureHpkePrivateKey {
    /// Creates a new secure HPKE private key from raw bytes.
    ///
    /// The bytes are wrapped in a `Zeroizing` container for automatic cleanup.
    pub fn new(key_bytes: Vec<u8>) -> Self {
        Self {
            key_bytes: Zeroizing::new(key_bytes),
        }
    }

    /// Returns an `HpkePrivateKey` for use with rustls HPKE operations.
    ///
    /// Note: The returned `HpkePrivateKey` contains a copy of the key bytes.
    /// This copy is not zeroized by rustls, but is short-lived (used only
    /// during the HPKE decryption operation).
    pub fn as_hpke_private_key(&self) -> HpkePrivateKey {
        self.key_bytes.to_vec().into()
    }
}

/// Calls KMS decrypt via the Nitro Enclaves SDK FFI wrapper.
///
/// # Arguments
///
/// * `credential` - AWS credentials for KMS access
/// * `ciphertext` - Base64-encoded ciphertext to decrypt
/// * `region` - AWS region where the KMS key resides
///
/// # Returns
///
/// Returns the decrypted plaintext bytes.
fn call_kms_decrypt(credential: &Credential, ciphertext: &str, region: &str) -> Result<Vec<u8>> {
    // Base64 decode the ciphertext
    let ciphertext_bytes = ciphertext.decode_hex()?;

    // Call FFI wrapper directly instead of spawning subprocess
    aws_ne::kms_decrypt(
        region.as_bytes(),
        credential.access_key_id.as_bytes(),
        credential.secret_access_key.as_bytes(),
        credential.session_token.as_bytes(),
        &ciphertext_bytes,
    )
    .map_err(|e| anyhow!("KMS decrypt failed: {}", e))
}

// encrypt message which encode by bs64
pub fn call_kms_encrypt(
    credential: &Credential,
    plaintext: &str,
    region: &str,
    key_id: &str,
) -> Result<Vec<u8>> {
    // Base64 decode the ciphertext
    let plaintext_bytes = plaintext.as_bytes();

    // Call FFI wrapper directly instead of spawning subprocess
    aws_ne::kms_encrypt(
        region.as_bytes(),
        credential.access_key_id.as_bytes(),
        credential.secret_access_key.as_bytes(),
        credential.session_token.as_bytes(),
        plaintext_bytes,
        &key_id,
    )
    .map_err(|e| anyhow!("KMS encrypt failed: {}", e))
}

//解密在设备注册时候的密文结果获取tee的密钥公钥明文
pub fn get_tee_client(
    payload: &EnclaveRequest<CreateWalletKeyRequest>,
    device_ciphertext: &str,
) -> Result<TeeClient> {
    println!("{}:{}", file!(), line!());
    let plaintext = call_kms_decrypt(
        &payload.credential,
        device_ciphertext,
        &payload.request.region,
    )
    .map_err(|err| anyhow!("failed to call KMS: {err:?}"))?;

    let client: TeeClient = serde_json::from_slice(&plaintext)?;
    if client.usage != Usage::RegisterTeeDevice {
        bail!("Usage not matched!");
    }
    println!(
        "[enclave:plaintext_pubkey] KMS decrypted private key length: {:?}",
        client
    );

    Ok(client)
}

use crate::model::RecoverWalletRequest;
//todo: 整理
pub fn get_tee_client2(payload: &EnclaveRequest<RecoverWalletRequest>) -> Result<TeeClient> {
    println!("{}:{}", file!(), line!());
    let plaintext = call_kms_decrypt(
        &payload.credential,
        &payload.request.new_device_ciphertext,
        &payload.request.region,
    )
    .map_err(|err| anyhow!("failed to call KMS: {err:?}"))?;

    let client: TeeClient = serde_json::from_slice(&plaintext)?;
    if client.usage != Usage::RegisterTeeDevice {
        bail!("Usage not matched!");
    }
    println!(
        "[enclave:plaintext_pubkey] KMS decrypted private key length: {:?}",
        client
    );

    Ok(client)
}

//解密在设备注册时候的密文结果获取tee的密钥公钥明文
pub fn get_wallet_key_bond(
    credential: &Credential,
    ciphertext: &str,
    region: &str,
) -> Result<WalletKeyBond> {
    println!("{}:{}", file!(), line!());
    let plaintext = call_kms_decrypt(credential, ciphertext, region)
        .map_err(|err| anyhow!("failed to call KMS: {err:?}"))?;

    let client: WalletKeyBond = serde_json::from_slice(&plaintext)?;
    if client.usage != Usage::CreateWalletKey {
        bail!("Usage is {}.expect CreatedWalletKey", client.usage);
    }
    println!(
        "[enclave:plaintext_pubkey] KMS decrypted private key length: {:?}",
        client
    );

    Ok(client)
}
