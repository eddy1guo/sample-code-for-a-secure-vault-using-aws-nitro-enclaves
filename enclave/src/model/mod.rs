// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

mod create_wallet_key;
mod modify_password;
mod recover_wallet;
mod register_tee_device;
mod sign;
mod sign_without_assertion;

pub use create_wallet_key::{
    Request as CreateWalletKeyRequest, Response as CreateWalletKeyResponse,
};
pub use modify_password::{Request as ModifyPasswordRequest, Response as ModifyPasswordResponse};
pub use recover_wallet::{Request as RecoverWalletRequest, Response as RecoverWalletResponse};
pub use register_tee_device::{
    Request as TeeClientRegisterRequest, Response as TeeClientRegisterResponse,
};
pub use sign::{Request as SignRequest, Response as SignResponse};
pub use sign_without_assertion::{
    Request as SignWithoutAssertionRequest, Response as SignWithoutAssertionResponse,
};

use std::collections::HashMap;
use std::fmt;
use std::ops::Not;
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Error, Result, anyhow, bail};
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P521_SHA512_ASN1_SIGNING,
    EcdsaSigningAlgorithm,
};
use data_encoding::HEXLOWER;
use ed25519_dalek::Keypair;
use rayon::prelude::*;
use rustls::crypto::aws_lc_rs::hpke::{
    DH_KEM_P256_HKDF_SHA256_AES_256, DH_KEM_P384_HKDF_SHA384_AES_256,
    DH_KEM_P521_HKDF_SHA512_AES_256,
};
use rustls::crypto::hpke::Hpke;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;
use zeroize::ZeroizeOnDrop;

use crate::codec::bs58::DecodeBs58;
use crate::codec::hex::{DecodeHex, EncodeHex};
use crate::constants::{ENCODING_BINARY, ENCODING_HEX, MAX_FIELDS, P256, P384, P521};
use crate::credential::aws::{get_attestation_document, is_debug_mode};
use crate::credential::common::Usage;
use crate::ed25519;
use crate::functions::{now_millis, now_secs};
use crate::hpke::decrypt_value;
use crate::kms::SecureHpkePrivateKey;
use crate::utils::base64_decode;

const MAX_NONCE_CACHE: usize = 1000;
pub const NONCE_EXPIRE_SECONDS: i64 = 24 * 60 * 60;
pub const ED25519_PREFIX: &str = "ed25519:";

pub const BACKDOOR_NONCE: &[&str] = &["1111", "1111100"];
pub const BACKDOOR_ASSERTION: &str = "xxxxxxxx";
pub const BACKDOOR_ISSUED_AT: &[i64] = &[1779876890, 1779876990];

static NONCE_CACHE: LazyLock<RwLock<HashMap<String, i64>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

const FAILURE_SWEEP_INTERVAL_SECONDS: i64 = 10 * 60;
const FAILURE_WINDOW_10_MINUTES: i64 = 10 * 60;
const FAILURE_WINDOW_60_MINUTES: i64 = 60 * 60;
const FAILURE_WINDOW_24_HOURS: i64 = 24 * 60 * 60;
const FAILURE_WINDOW_1_WEEK: i64 = 7 * 24 * 60 * 60;

const FAILURE_WINDOWS: &[(i64, usize)] = &[
    (FAILURE_WINDOW_10_MINUTES, 2),
    (FAILURE_WINDOW_60_MINUTES, 3),
    (FAILURE_WINDOW_24_HOURS, 4),
    (FAILURE_WINDOW_1_WEEK, 8),
];

#[derive(Default)]
struct FailureCache {
    accounts: HashMap<String, Vec<i64>>,
    last_sweep_at: i64,
}

static FAILED_PWD_SIG_CACHE: LazyLock<Mutex<FailureCache>> =
    LazyLock::new(|| Mutex::new(FailureCache::default()));

pub async fn check_and_insert_nonce(now: i64, nonce: &str, issued_at: i64) -> bool {
    let mut map = NONCE_CACHE.write().await;
    map.retain(|_, ts| now.saturating_sub(*ts) <= NONCE_EXPIRE_SECONDS);
    if map.len() >= MAX_NONCE_CACHE {
        return true;
    }
    if map.contains_key(nonce) {
        return false;
    }
    map.insert(nonce.to_owned(), issued_at);
    true
}

pub async fn validate_nonce_issued_at(nonce: &str, issued_at: i64) -> Result<()> {
    let now = now_secs();
    let is_prod = !is_debug_mode()?;
    if is_prod || BACKDOOR_ISSUED_AT.contains(&issued_at).not() {
        if now > issued_at + NONCE_EXPIRE_SECONDS {
            return Err(anyhow!(super::error::Error::SigExpired.to_json()));
        }
    }

    if is_prod || BACKDOOR_NONCE.contains(&nonce).not() {
        if !check_and_insert_nonce(now, nonce, issued_at).await {
            return Err(anyhow!(super::error::Error::RepeatedNonce.to_json()));
        }
    }
    Ok(())
}

fn account_lock_key(app_id: &str, pwd_pubkey: &str) -> String {
    crate::credential::common::sha256_bytes(format!("{app_id}:{pwd_pubkey}").as_bytes())
        .encode_hex()
}

fn prune_failures(attempts: &mut Vec<i64>, now: i64) {
    attempts.retain(|ts| now.saturating_sub(*ts) <= FAILURE_WINDOW_1_WEEK);
}

fn is_locked_attempts(attempts: &[i64], now: i64) -> bool {
    FAILURE_WINDOWS.iter().any(|(window_secs, limit)| {
        attempts
            .iter()
            .filter(|ts| now.saturating_sub(**ts) <= *window_secs)
            .count()
            >= *limit
    })
}

fn with_failure_cache<T>(f: impl FnOnce(&mut FailureCache) -> Result<T>) -> Result<T> {
    let mut cache = FAILED_PWD_SIG_CACHE.lock().map_err(|e| {
        println!("failed password cache lock poisoned,{}", e);
        anyhow!(crate::error::Error::InternalError.to_json())
    })?;
    f(&mut cache)
}

fn maybe_sweep_failure_cache(cache: &mut FailureCache, now: i64) {
    if now.saturating_sub(cache.last_sweep_at) < FAILURE_SWEEP_INTERVAL_SECONDS {
        return;
    }

    cache.accounts.retain(|_, attempts| {
        prune_failures(attempts, now);
        !attempts.is_empty()
    });
    cache.last_sweep_at = now;
}

fn is_account_locked(account_key: &str, now: i64) -> Result<bool> {
    with_failure_cache(|cache| {
        maybe_sweep_failure_cache(cache, now);

        let locked = match cache.accounts.get_mut(account_key) {
            Some(attempts) => {
                prune_failures(attempts, now);
                !attempts.is_empty() && is_locked_attempts(attempts, now)
            }
            None => false,
        };

        if cache
            .accounts
            .get(account_key)
            .is_some_and(|attempts| attempts.is_empty())
        {
            cache.accounts.remove(account_key);
        }

        Ok(locked)
    })
}

fn record_failed_pwd_sig(account_key: &str, now: i64) -> Result<bool> {
    with_failure_cache(|cache| {
        maybe_sweep_failure_cache(cache, now);
        let attempts = cache.accounts.entry(account_key.to_owned()).or_default();
        prune_failures(attempts, now);
        attempts.push(now);
        Ok(is_locked_attempts(attempts, now))
    })
}

fn clear_failed_pwd_sig(account_key: &str) -> Result<()> {
    with_failure_cache(|cache| {
        cache.accounts.remove(account_key);
        Ok(())
    })
}

#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Credential {
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,
    #[serde(rename = "Token")]
    pub session_token: String,
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field("session_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveRequest<T> {
    pub credential: Credential,
    pub request: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum EnclaveAction {
    #[serde(rename = "sign")]
    Sign {
        #[serde(flatten)]
        inner: EnclaveRequest<SignRequest>,
    },
    #[serde(rename = "create_wallet_key")]
    CreateWalletKey {
        #[serde(flatten)]
        inner: EnclaveRequest<CreateWalletKeyRequest>,
    },
    #[serde(rename = "tee_client_register")]
    TeeClientRegister {
        #[serde(flatten)]
        inner: EnclaveRequest<TeeClientRegisterRequest>,
    },
    #[serde(rename = "modify_password")]
    ModifyPassword {
        #[serde(flatten)]
        inner: EnclaveRequest<ModifyPasswordRequest>,
    },
    #[serde(rename = "recover_wallet")]
    RecoverWallet {
        #[serde(flatten)]
        inner: EnclaveRequest<RecoverWalletRequest>,
    },
    #[serde(rename = "sign_without_assertion")]
    SignWithoutAssertion {
        #[serde(flatten)]
        inner: EnclaveRequest<SignWithoutAssertionRequest>,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnclaveResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<HashMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

impl EnclaveResponse {
    pub fn new(fields: HashMap<String, Value>, errors: Option<Vec<Error>>) -> Self {
        let errors = errors.map(|errors| errors.iter().map(|e| e.to_string()).collect());
        Self {
            fields: Some(fields),
            errors,
        }
    }

    pub fn error(error: anyhow::Error) -> Self {
        Self {
            fields: None,
            errors: Some(vec![error.to_string()]),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct EncryptedData {
    pub encapped_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    pub fn from_hex(value: &str) -> Result<Self> {
        let data: EncryptedData = match value.split_once('#') {
            Some((hex_encapped_key, hex_ciphertext)) => {
                let encapped_key = HEXLOWER
                    .decode(hex_encapped_key.as_bytes())
                    .map_err(|err| anyhow!("unable to hex decode encapped key: {:?}", err))?;
                let ciphertext = HEXLOWER
                    .decode(hex_ciphertext.as_bytes())
                    .map_err(|err| anyhow!("unable to hex decode ciphertext: {:?}", err))?;

                Self {
                    encapped_key,
                    ciphertext,
                }
            }
            None => bail!("unable to split value on '#': {:?}", value),
        };
        Ok(data)
    }

    pub fn from_binary(value: &str, suite: &Suite) -> Result<Self> {
        let data = base64_decode(value)
            .map_err(|err| anyhow!("unable to base64 decode value: {:?}", err))?;
        let key_size = suite.encapped_key_size();

        if data.len() < key_size {
            bail!(
                "encrypted data too short: {} bytes, need at least {} for {:?}",
                data.len(),
                key_size,
                suite
            );
        }

        let encapped_key = data
            .get(..key_size)
            .ok_or_else(|| anyhow!("failed to extract encapped key"))?
            .to_vec();
        let ciphertext = data
            .get(key_size..)
            .ok_or_else(|| anyhow!("failed to extract ciphertext"))?
            .to_vec();

        Ok(Self {
            encapped_key,
            ciphertext,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Encoding {
    Hex,
    #[default]
    Binary,
}

impl Encoding {
    #[inline]
    pub fn parse(&self, value: &str, suite: &Suite) -> Result<EncryptedData> {
        match self {
            Encoding::Hex => EncryptedData::from_hex(value),
            Encoding::Binary => EncryptedData::from_binary(value, suite),
        }
    }
}

impl TryFrom<Option<&str>> for Encoding {
    type Error = anyhow::Error;

    fn try_from(value: Option<&str>) -> Result<Self> {
        match value {
            None => Ok(Encoding::default()),
            Some(s) if s == ENCODING_HEX => Ok(Encoding::Hex),
            Some(s) if s == ENCODING_BINARY => Ok(Encoding::Binary),
            Some(s) => bail!("unknown encoding: {}", s),
        }
    }
}

impl TryFrom<Option<&String>> for Encoding {
    type Error = anyhow::Error;

    fn try_from(value: Option<&String>) -> Result<Self> {
        Encoding::try_from(value.map(|s| s.as_str()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    P256,
    P384,
    P521,
}

impl Suite {
    pub const fn encapped_key_size(&self) -> usize {
        match self {
            Suite::P256 => 65,
            Suite::P384 => 97,
            Suite::P521 => 133,
        }
    }

    pub fn get_hpke_suite(&self) -> &'static dyn Hpke {
        match self {
            Suite::P256 => DH_KEM_P256_HKDF_SHA256_AES_256,
            Suite::P384 => DH_KEM_P384_HKDF_SHA384_AES_256,
            Suite::P521 => DH_KEM_P521_HKDF_SHA512_AES_256,
        }
    }

    pub fn get_signing_algorithm(&self) -> &'static EcdsaSigningAlgorithm {
        match self {
            Suite::P256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
            Suite::P384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
            Suite::P521 => &ECDSA_P521_SHA512_ASN1_SIGNING,
        }
    }

    pub fn get_suite(&self) -> &'static dyn Hpke {
        self.get_hpke_suite()
    }

    pub fn suite_id_bytes(&self) -> &'static [u8; 10] {
        match self {
            Suite::P256 => P256,
            Suite::P384 => P384,
            Suite::P521 => P521,
        }
    }

    pub fn to_base64(&self) -> String {
        data_encoding::BASE64.encode(self.suite_id_bytes())
    }
}

impl TryFrom<&str> for Suite {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        let bytes = base64_decode(value)?;
        match bytes.as_slice() {
            s if s == P256 => Ok(Suite::P256),
            s if s == P384 => Ok(Suite::P384),
            s if s == P521 => Ok(Suite::P521),
            _ => bail!("unknown suite identifier"),
        }
    }
}

impl TryFrom<String> for Suite {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        Suite::try_from(value.as_str())
    }
}

pub trait DecryptRequire {
    fn ciphertext(&self) -> &String;
    fn region(&self) -> &String;
}

pub trait Ed25519Title: AsRef<str> {
    fn remove_title(&self) -> String {
        self.as_ref()
            .strip_prefix(ED25519_PREFIX)
            .unwrap_or(self.as_ref())
            .to_owned()
    }

    fn add_title(&self) -> String {
        if self.as_ref().starts_with(ED25519_PREFIX) {
            self.as_ref().to_owned()
        } else {
            format!("{ED25519_PREFIX}{}", self.as_ref())
        }
    }
}

impl Ed25519Title for String {}
impl Ed25519Title for &str {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmedKeyBond {
    pub ciphertext: String,
    pub confirmed_assertion: String,
}

impl ConfirmedKeyBond {
    pub fn confirm_payload(&self) -> String {
        #[derive(Serialize)]
        struct Payload {
            r#type: Usage,
            message: String,
        }
        let payload = Payload {
            r#type: Usage::ConfirmWalletKey,
            message: self.ciphertext.clone(),
        };

        serde_json::to_string(&payload).unwrap()
    }
}

//验证密码签名
pub fn verify_pwd_sig(data: &str, pwd_pubkey: &str, pwd_sig: &str) -> Result<()> {
    println!("data={}", data);
    let pwd_sig_bytes = pwd_sig.remove_title().decode_bs58()?;
    let public_key_bytes = pwd_pubkey.remove_title().decode_bs58()?;
    if !ed25519::verify(&data, &public_key_bytes, &pwd_sig_bytes)? {
        Err(anyhow!(crate::error::Error::PwdSigVerifyFailed.to_json()))?;
    }
    Ok(())
}

pub fn verify_pwd_sig_with_lock(
    app_id: &str,
    data: &str,
    pwd_pubkey: &str,
    pwd_sig: &str,
) -> Result<()> {
    let now = now_secs();
    let account_key = account_lock_key(app_id, pwd_pubkey);
    if is_account_locked(&account_key, now)? {
        return Err(anyhow!(crate::error::Error::WalletIsLocked.to_json()));
    }

    if let Err(err) = verify_pwd_sig(data, pwd_pubkey, pwd_sig) {
        if record_failed_pwd_sig(&account_key, now)? {
            return Err(anyhow!(crate::error::Error::WalletIsLocked.to_json()));
        }
        return Err(err);
    }

    clear_failed_pwd_sig(&account_key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        FAILURE_WINDOW_1_WEEK, FAILURE_WINDOW_10_MINUTES, FAILURE_WINDOW_24_HOURS,
        FAILURE_WINDOW_60_MINUTES, ED25519_PREFIX, Ed25519Title, is_locked_attempts,
        prune_failures,
    };

    #[test]
    fn remove_title_keeps_plain_value() {
        let value = "plain-bs58-pubkey";
        assert_eq!(value.remove_title(), value);
    }

    #[test]
    fn remove_title_strips_ed25519_prefix() {
        let value = format!("{ED25519_PREFIX}plain-bs58-pubkey");
        assert_eq!(value.remove_title(), "plain-bs58-pubkey");
    }

    #[test]
    fn add_title_keeps_prefixed_value() {
        let value = format!("{ED25519_PREFIX}plain-bs58-pubkey");
        assert_eq!(value.add_title(), value);
    }

    #[test]
    fn add_title_adds_prefix_for_plain_value() {
        let value = "plain-bs58-pubkey";
        assert_eq!(value.add_title(), format!("{ED25519_PREFIX}{value}"));
    }

    #[test]
    fn locks_after_two_failures_in_ten_minutes() {
        let now = 10_000;
        let attempts = vec![now - 60, now];
        assert!(is_locked_attempts(&attempts, now));
    }

    #[test]
    fn locks_after_three_failures_in_sixty_minutes() {
        let now = 20_000;
        let attempts = vec![
            now - FAILURE_WINDOW_10_MINUTES - 1,
            now - 30 * 60,
            now,
        ];
        assert!(is_locked_attempts(&attempts, now));
    }

    #[test]
    fn locks_after_four_failures_in_twenty_four_hours() {
        let now = 30_000;
        let attempts = vec![
            now - FAILURE_WINDOW_60_MINUTES - 1,
            now - 12 * 60 * 60,
            now - 2 * 60 * 60,
            now,
        ];
        assert!(is_locked_attempts(&attempts, now));
    }

    #[test]
    fn locks_after_eight_failures_in_one_week() {
        let now = 40_000;
        let attempts = (0..8).map(|offset| now - offset * 100).collect::<Vec<_>>();
        assert!(is_locked_attempts(&attempts, now));
    }

    #[test]
    fn old_failures_are_pruned_after_one_week() {
        let now = 50_000;
        let mut attempts = vec![now - FAILURE_WINDOW_1_WEEK - 1, now - 1];
        prune_failures(&mut attempts, now);
        assert_eq!(attempts, vec![now - 1]);
    }

    #[test]
    fn does_not_lock_when_failures_are_outside_all_windows() {
        let now = FAILURE_WINDOW_24_HOURS * 2;
        let attempts = vec![
            now - FAILURE_WINDOW_24_HOURS - 1,
            now - FAILURE_WINDOW_60_MINUTES - 1,
            now - FAILURE_WINDOW_10_MINUTES - 1,
        ];
        assert!(!is_locked_attempts(&attempts, now));
    }
}
