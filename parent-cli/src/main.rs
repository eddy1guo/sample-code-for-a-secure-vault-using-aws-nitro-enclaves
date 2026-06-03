use std::str::FromStr;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use enclave_vault::codec::{bs58::EncodeBs58, bs64::EncodeBs64, hex::DecodeHex};
use enclave_vault::credential::aws;
use enclave_vault::credential::common::Platform;
use enclave_vault::ed25519;
use enclave_vault::model::ModifyPasswordResponse;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEFAULT_BASE_URL: &str = "https://localhost:10001";
const REGION: &str = "ap-southeast-1";
const KEY_ID: &str = "mrk-794e2c0173cd4848849739bf393a76b5";
const PLACEHOLDER_MESSAGE: &str = "hello-wallet-sign";
const RECOVERY_PLACEHOLDER_MESSAGE: &str = "reocover_wallet_message";
const PASSWORD_SEED: &str = "123456";
const NEW_PASSWORD_SEED: &str = "223456";
const MODIFY_PASSWORD_ASSERTION: &str = "xxxx";
const PLACEHOLDER_RECOVER_ASSERTION: &str = "xxxx";
const PLACEHOLDER_NEW_DEVICE_CONFIRMED_ASSERTION: &str = "xxxx";
const PLACEHOLDER_SIGN_WITHOUT_ASSERTION_SIGN_ASSERTION: &str = "xxxx";
const FIXED_PWD_SIGN_PAYLOAD: &str =
    r#"{"type":"Sign","message": "xxxx","issued_at":1779876890,"nonce":"1111"}"#;

const APPLE_KEY_ID: &str = "LnxoVdHGe+HnCcwS7FCWJecITXf2KlJBoHO7/Jr4DFI=";

//    {"type":"TeeClientRegister","issued_at":1779876890,"nonce":"1111"}
const NONCE: &str = "1111";
const ISSUED_AT: i64 = 1779876890;
const NEW_DEVICE_NONCE: &str = "1111100";
const NEW_DEVICE_ISSUED_AT: i64 = 1779876990;
const GOOGLE_ATTESTATION: [&str; 5] = [
    "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",
];
const FIX_DEVICE_CIPHERTEXT: &str = "0102020078b745c66ff477962a0c7936db47664e72366aea22ffbe5c791a8b8de1d273e9d701bec18902886bdfb420c6e57eddfb3695000001443082014006092a864886f70d010706a08201313082012d0201003082012606092a864886f70d010701301e060960864801650304012e3011040c0fdff1d96e95dc283b814d480201108081f8c319d95637289019b1aae29bc8483de07f4c0eba0411260dde108d21e0b13b53ca74cd1d4b6d58a1891452f3cf1b73970334402aa7c9c8959ec60cb5e0e2f9cdf19a49320fcf607c5aee10fb7baabb1f13c86c789dcc13bdc00a88bd049452c42272df2a3b9465ea503c254c5d1dcc797e8a0f9033f0099a549f6416947867712200c30114d932b9aef28f1a05f1867225d4733a3dea7d8d8713e6efa36a701c9490d26366b9632057d49f79c5699459fd71b6ae43d674aa570a9e9f25fd592e9623fc2046a7aac30290ab2867db94c63915e7070592e1c464c506b1b89e3007ffa2a1313f3cc6fd69bb40b943f7c0eecbb14cfb269fe8db";
const FIX_NEW_DEVICE_CIPHERTEXT: &str = "0102020078b745c66ff477962a0c7936db47664e72366aea22ffbe5c791a8b8de1d273e9d7014ac3857105be2544f2d723bbb2a35792000001443082014006092a864886f70d010706a08201313082012d0201003082012606092a864886f70d010701301e060960864801650304012e3011040cf1cc21aa19917102b63795b00201108081f8a1d92e102106d4dab11bf7e56d400ba91436b5938d862ee4989797038c40886dc845e022df197dd3391c5c64df15a27faf65fee055f6228b6dbd02c806cac567e3dc5b1161fdf1cbf6dc3ed99adb61f9d1265e476907d79d62dacc6d25e6f332e25c6784c6e1e04b93488b90e61be93758a2f2a2384b6ac69ea4fa05a973cc3acda6df32afa0cf68af04a9ac193ed7f70251bf0a8a38ed08a63d25ac7e18885327f1717a840c73d2db570a39b0d68ac22ce30faaf17cefa78df6caa8e3f02764cf1283fb3c1497f2ddb512490c545db16744f1a072b136839b6832e0169cfa070ef0ded4034e792331d6e1eaf560dd301a61da6d5e2f075f";

const FIX_KEY_BOND_CIPHERTEXT: &str = "0102020078b745c66ff477962a0c7936db47664e72366aea22ffbe5c791a8b8de1d273e9d701b387059a1e649db8e764e314ca6e0b24000002a03082029c06092a864886f70d010706a082028d308202890201003082028206092a864886f70d010701301e060960864801650304012e3011040c0b2385272435118ed332eb6d02011080820253b5f3bf4fa355fdb0e1d54865df052736484877c4cdd5ccfbc87480bec13b051e4e49024efb6c7b37545ab6bc425ccda9b14d8b691ecbf6a374316ce2331de30579e99b8733b432d02eb3500934d30efdf30fe190479edc75794e5bbc556fa26d6df7025cabc16d3d33eb9768f7bd6836dd7f4f5714b3f0d41969c1dbbf36437ec80909a8482f22cfc54270b692b3fc7d2dea1a590385832ba9bb28fb8e157d11462d3482a88602dab9891d1b8e9a03e4396ea4469f65a3ba8f5fce56cce55b144926fc6334cc4c7993d17f5655c55fc5a9dbab0e3024f4c2b52c81379a3493a4461e256ad36de16512cb38d50efcab9a521f10b43cd26fc017c35b6ebf828dc0dff7729b38db8e9cd6340f2555fd3e8db0515b1a143886da55b5c33eb3f90da48938d6d7a1e91bc3b6f6d4188e9c15a0d7e812e9b0f6764a558ab0d1714e114008c8d31d954c0972de7ab4f8addd2923527a541bd6a230b83413f47d07108c58c6a9387aea507500051c748fd79f3ffc3133db26184f2625624af0a24edfffb5cecbfd29db7bf8d390ada90a49f6be5d96cdd160971fcbbb327452363ea2013a620b6493158bc289b383a30117e36deb5438e6804a87ddf8982b0bcea9dabc9c14e43e7733ba19a0f00acc78877497508f54bebc73c700e6a1a8bc4993129e78a6c82ccfa812691e3866ee89c5be98a0bf29a93a60ee6dcde8fa91dd1145efe0d322c0af6892dfe9eddaff76611179c810a455566a58a511cd872b3c5326853f36b821d83306c9a2cb0fa026bd56b0214b302b74b87821409bd0b3b8cfc993397b5f47bd090c088b511d9dc63b5b1899e4f8fe";
const CONFIRM_DEVICE_ASSERTION: &str = "MEQCIAR5vzfjU8+zpQ/jU2mZdgSYYO3OFw9g9VEAGIg9RbqsAiAi/r5y+OaQAVsLI5Zi6Z5m7wkZcihbr5Uz8iDSYp5jhA==";
const CREATE_KEY_ASSERTION: &str = "MEUCIQDkUENQfUm7y4fk+M1Xml2LpCtox3m09reCFClLidiOAwIgOKwT/RR5uwYvHxd9uWtfCAVIKbact5vD7YcA6tqZiXI=";
const CONFIRM_KEY_ASSERTION: &str = "MEQCICy9lFgMfDtfh2C0LiwiV2zvifYz3bKI/qj9LP2LaxsQAiAcHScuvIvfexXRhn8ljHmUWb8j+zEi08AUhSWpAQAVlQ==";
const SIGN_ASSERTION: &str = "MEQCIGkPGoSm8cBNfUShXdCOMPcR+ulQQ14wEq+0O/V1yTu7AiAwVqL5mT642qXO4b1I04sAMd9IWZngX/zB2gRHOp9mRw==";
// {"type":"ConfirmTeeDevice","message": "xx_tee_device_cipher_text_xx"}
const CONFIRM_TEE_CLIENT_REGISTER_ASSERTION: &str = "LnxoVdHGe+HnCcwS7FCWJecITXf2KlJBoHO7/Jr4DFI=";

// {"type":"Sign","message": "xxxx","issued_at":1779876890,"nonce":"1111"}

// {"type":"ConfirmWalletKey","message": "xx_wallet_key_cipher_text_xx"}
const CONFIRM_KEY_BOND_ASSERTION: &str = "LnxoVdHGe+HnCcwS7FCWJecITXf2KlJBoHO7/Jr4DFI=";

//device_confirmed_assertion: PLACEHOLDER_SIG.to_string(),

//        create_key_assertion: PLACEHOLDER_SIG.to_string(),

//r#"{"type":"Sign","message": "xxxx","issued_at":1779876890,"nonce":"1111"}"#;

// {"type":"RegisterTeeDevice","issued_at":1779876890,"nonce":"1111"}
// {"type":"ConfirmTeeDevice","message": "xxxx"}
// {"type":"CreateWalletKey","message": "xxxx","issued_at":1779876890,"nonce":"1111"}
// {"type":"ConfirmWalletKey","message": "xxxx"}
// {"type":"Sign","message": "xxxx","issued_at":1779876890,"nonce":"1111"}
// {"type":"SignWithoutAssertion","message": "xxxx","issued_at":1779876890,"nonce":"1111"}
// {"type":"RecoverWallet","issued_at":1779876890,"nonce":"1111"}
// {"type":"ModifyPassword","issued_at":1779876890,"nonce":"1111"}

// todo: 每次新建的key都需要新的签名太麻烦，后续前两个流程正常走，后续的业务如果需要可以使用固定的assertion
pub fn register_tee_device_payload() -> String {
    format!(
        "{{\"type\":\"RegisterTeeDevice\",\"issued_at\":{},\"nonce\":\"{}\"}}",
        ISSUED_AT, NONCE
    )
}

// as another xiaomi divece
pub fn register_tee_device_payload2() -> String {
    format!(
        "{{\"type\":\"RegisterTeeDevice\",\"issued_at\":{},\"nonce\":\"{}\"}}",
        NEW_DEVICE_ISSUED_AT, NEW_DEVICE_NONCE
    )
}

pub fn confirm_tee_device_payload(device_ciphertext: &str) -> String {
    format!(
        "{{\"type\":\"ConfirmTeeDevice\",\"message\":\"{}\"}}",
        device_ciphertext
    )
}

pub fn create_wallet_key_payload() -> String {
    format!(
        "{{\"type\":\"CreateWalletKey\",\"issued_at\":{},\"nonce\":\"{}\"}}",
        ISSUED_AT, NONCE
    )
}

pub fn confirm_wallet_key_payload(key_ciphertext: &str) -> String {
    format!(
        "{{\"type\":\"ConfirmWalletKey\",\"message\":\"{}\"}}",
        key_ciphertext
    )
}

pub fn sign_payload(message: &str) -> String {
    format!(
        "{{\"type\":\"Sign\",\"message\":\"{}\",\"issued_at\":{},\"nonce\":\"{}\"}}",
        message, ISSUED_AT, NONCE
    )
}

pub fn sign_without_assertion_payload(message: &str) -> String {
    format!(
        "{{\"type\":\"SignWithoutAssertion\",\"message\":\"{}\",\"issued_at\":{},\"nonce\":\"{}\"}}",
        message, ISSUED_AT, NONCE
    )
}

pub fn recover_wallet_payload() -> String {
    format!(
        "{{\"type\":\"RecoverWallet\",\"issued_at\":{},\"nonce\":\"{}\"}}",
        ISSUED_AT, NONCE
    )
}

pub fn modify_password_payload() -> String {
    format!(
        "{{\"type\":\"ModifyPassword\",\"issued_at\":{},\"nonce\":\"{}\"}}",
        ISSUED_AT, NONCE
    )
}

#[derive(Parser)]
#[command(name = "parent-cli")]
#[command(about = "CLI for basic parent HTTP interactions")]
struct Cli {
    #[arg(long, default_value = DEFAULT_BASE_URL)]
    base_url: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    RunBasic,
}

#[derive(Debug, Serialize)]
struct TeeClientRegisterRequest {
    attestation: Vec<String>,
    platform: String,
    issued_at: i64,
    nonce: String,
    key_id: String,
    region: String,
}

#[derive(Debug, Serialize)]
struct CreateWalletKeyRequest {
    device_ciphertext: String,
    device_confirmed_assertion: String,
    bind_device_ciphertext: String,
    bind_device_confirmed_assertion: String,
    master_key_bond_ciphertext: Option<String>,
    master_key_bond_confirmed_assertion: Option<String>,
    pwd_pubkey: String,
    pwd_sig: String,
    create_key_assertion: String,
    issued_at: i64,
    nonce: String,
    key_id: String,
    region: String,
}

#[derive(Debug, Serialize)]
struct SignRequest {
    key_bond_ciphertext: String,
    key_bond_confirmed_assertion: String,
    pwd_sig: String,
    sign_assertion: String,
    message: String,
    issued_at: i64,
    nonce: String,
    region: String,
}

#[derive(Debug, Serialize, Clone)]
struct ConfirmedKeyBond {
    ciphertext: String,
    confirmed_assertion: String,
}

#[derive(Debug, Serialize)]
struct ModifyPasswordRequest {
    key_bonds: Vec<ConfirmedKeyBond>,
    new_pwd_pubkey: String,
    new_pwd_sig: String,
    assertion: String,
    issued_at: i64,
    nonce: String,
    key_id: String,
    region: String,
}

#[derive(Debug, Serialize)]
struct RecoverWalletRequest {
    new_device_ciphertext: String,
    new_device_confirmed_assertion: String,
    key_bonds: Vec<ConfirmedKeyBond>,
    pwd_sig: String,
    assertion: String,
    issued_at: i64,
    nonce: String,
    key_id: String,
    region: String,
}

#[derive(Debug, Serialize)]
struct SignWithoutAssertionRequest {
    key_bond_ciphertext: String,
    key_bond_confirmed_assertion: String,
    pwd_sig: String,
    message: String,
    issued_at: i64,
    nonce: String,
    region: String,
}

#[derive(Debug, Deserialize)]
struct RegisterTeeDeviceResponse {
    client_ciphertext: String,
}

#[derive(Debug, Deserialize)]
struct CreateWalletKeyResponse {
    key_bond_ciphertext: String,
    wallet_pubkey: String,
}

#[derive(Debug, Deserialize)]
struct SignResponse {
    sig: String,
}

#[derive(Debug, Deserialize)]
struct ApiResponse {
    fields: std::collections::BTreeMap<String, Value>,
    #[serde(default)]
    errors: Option<Vec<String>>,
}

pub fn generate_tee_attestation(platform: &str, message: &str, times: u8) -> Vec<String> {
    println!("message: {}", message);
    let payload: Value = serde_json::from_str(message).unwrap();
    match (platform, payload["type"].as_str().unwrap(), times) {
        ("Google", "RegisterTeeDevice", 1) => {
            GOOGLE_ATTESTATION.iter().map(|x| x.to_string()).collect()
        }
        ("Google", "RegisterTeeDevice", 2) => {
            [
                "MIIC0DCCAnagAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQKEwNURUUxKTAnBgNVBAMTIDUyNWFhODg1YWQ3MTM2OGNlYzJhNzAxZTZiOTVkZmQ3MB4XDTcwMDEwMTAwMDAwMFoXDTQ4MDEwMTAwMDAwMFowHzEdMBsGA1UEAxMUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATa2yUthZwrihNsVSfknc4Uv1r7ipcPHzTEtFDcTNrVgRVe7nCKJB7LoS8C1xLVciIiadTr42nic459b+/Czcdno4IBhzCCAYMwDgYDVR0PAQH/BAQDAgeAMIIBbwYKKwYBBAHWeQIBEQSCAV8wggFbAgIBLAoBAQICASwKAQEERXsidHlwZSI6IlJlZ2lzdGVyVGVlRGV2aWNlIiwiaXNzdWVkX2F0IjoxNzc5ODc2OTkwLCJub25jZSI6IjExMTExMDAifQQAMFq/hT0IAgYBnoDpX/S/hUVKBEgwRjEgMB4EGGNvbS5jaGFpbmxlc3NhbmRyb2lkLmFwcAICAdgxIgQg+sYXRdwJA3hvue3mKpYrOZ9zSPC7b4mbgzJmdZEDO5wwgaWhCDEGAgECAgEDogMCAQOjBAICAQClBTEDAgEEqgMCAQG/g3gDAgECv4U+AwIBAL+FQEwwSgQgxdPHG8cNWOPgQJyp2bNMDbrB0vCaXelIpLjwkPGSaWUBAf8KAQAEIJqvC52VsnxoqY7f1TH86D49S1OAnpPL71WyXToG1QRFv4VBBQIDAiLgv4VCBQIDAxapv4VOBgIEATTaBb+FTwYCBAE02gUwCgYIKoZIzj0EAwIDSAAwRQIgQDpIu1rpOVNwbn35oHzdh37hyYUqO4JZy1fr7mf4a3sCIQCTk6q2o6yknGQMHf7JChUMf1o9ipsHSOeIZeH6Bs27AQ==",
                "MIIB3jCCAYWgAwIBAgIQUlqoha1xNozsKnAea5Xf1zAKBggqhkjOPQQDAjApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTMwHhcNMjYwNTI3MDk1NzQyWhcNMjYwNjExMTUxNTAyWjA5MQwwCgYDVQQKEwNURUUxKTAnBgNVBAMTIDUyNWFhODg1YWQ3MTM2OGNlYzJhNzAxZTZiOTVkZmQ3MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESOPhXFIK7RghTmGRwUT19AuqUHESrQQzthILbB5ETgZWzzZKu9WgZCCN6vmNtr0FNKzzQL6jDJOH35ydpPGBq6N/MH0wHQYDVR0OBBYEFLXyGUXXxnURX1R+G1HwO770s5+HMB8GA1UdIwQYMBaAFCE9xYxxu2HidmC48p1Nds23dRHZMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMBoGCisGAQQB1nkCAR4EDKIBGEADZlhpYW9taTAKBggqhkjOPQQDAgNHADBEAiALjnp6TrOTsXFJMlnTJLnwFV3pvrvYeFGteDkJDGromwIgAs5TR2s0ZNmMhj8BAZEZxargqVvtwpZBbWNN9dr6lqY=",
                "MIIC8TCCAnagAwIBAgIUANrEtHlUcQ2UImTAHCgf7fArQC0wCgYIKoZIzj0EAwMwKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EyMB4XDTI2MDUyODE2NDY1MVoXDTI2MDgwNjE2NDY1MFowKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGlIZB4hUMYY6QYuVAjwt7z35T+RBedWSETc4ZhSxjAIpVNx3c0P1M2oYLRf5B8VI0PKKu2/DnzvmtIpUsVRjy6OCAXowggF2MA4GA1UdDwEB/wQEAwICBDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQhPcWMcbth4nZguPKdTXbNt3UR2TAfBgNVHSMEGDAWgBRFIDI+H6b5jxzVw0cu1HpQ/juo4DCBjQYIKwYBBQUHAQEEgYAwfjB8BggrBgEFBQcwAoZwaHR0cDovL3ByaXZhdGVjYS1jb250ZW50LTY5YTQ3MjNiLTAwMDAtMjVhMi1hNzFjLTNjMjg2ZDM4ZWI5YS5zdG9yYWdlLmdvb2dsZWFwaXMuY29tLzg0OGI5N2RiMzBkNGVjYThhNGUyL2NhLmNydDCBggYDVR0fBHsweTB3oHWgc4ZxaHR0cDovL3ByaXZhdGVjYS1jb250ZW50LTY5YTQ3MjNiLTAwMDAtMjVhMi1hNzFjLTNjMjg2ZDM4ZWI5YS5zdG9yYWdlLmdvb2dsZWFwaXMuY29tLzg0OGI5N2RiMzBkNGVjYThhNGUyL2NybC5jcmwwCgYIKoZIzj0EAwMDaQAwZgIxAK6icj9CN1bBOSo4/MDqmjj5DYd5IAdu+O9HCDwGAHxOaZQWWZpKB5OCfgVTzy17uwIxAMoJd69U3Rqh01b8V5js5hPvlwvrDtxRFGHsGyWcVsNvdW/fKCFmdDmGP3+LX8x5EQ==",
                "MIICZTCCAeugAwIBAgIRALGEywXsUP3JhfDsUyl8+CMwCgYIKoZIzj0EAwMwUjEcMBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDETMBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjYwMjA5MTk1NzEwWhcNMjkwMjA4MTk1NzEwWjApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTIwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT19+tRAlmwuauVyRrgHqykkymaEkOS1IYSoXAQyBRvUNEnY5FGqmi44dOWcqMxu0uIbB3in5TD3GsR1NBmi3f//mI0aiARbBtdP3YaIff8yy076NY9dPMnBiCMIwjRR2Cjga0wgaowRwYDVR0fBEAwPjA8oDqgOIY2aHR0cHM6Ly9hbmRyb2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2tleV9jYTEuY3JsMB0GA1UdDgQWBBRFIDI+H6b5jxzVw0cu1HpQ/juo4DAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRSMrss+0ZDm9zWgakOZWbgNEHqQDAKBggqhkjOPQQDAwNoADBlAjBfOXmY1+SCcT/oWL17AuVS7uoxMXssLksjChHT+VhTMpWu9J42x3G20hHVGTj+3ZICMQDBYZjd7+vfuyLVCZkTX7wlvjcRJjvrEWyxvkZE5vlq8c3lwH9JyNBP3OeTd3o8IJs=",
                "MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEcMBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDETMBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0ExMRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQGEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCtG/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepAMAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifHEUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeYuR2zh/80lQyu9vAFCj6E4AXc+osmRg=="
            ].iter().map(|x| x.to_string()).collect()
        }
        ("Apple", "RegisterTeeDevice", 1) => vec![],
        ("Apple", "RegisterTeeDevice", 2) => vec![],
        _ => unreachable!(),
    }
}

// fake tee device and generate assertion
pub fn generate_tee_assertion(platform: &str, message: &str, times: u8) -> Result<String> {
    println!("message: {}", message);
    let payload: Value = serde_json::from_str(message)?;
    let assertion = match (platform, payload["type"].as_str().unwrap(),times) {
        ("Google", "ConfirmTeeDevice",1) => CONFIRM_DEVICE_ASSERTION.to_owned(),
        ("Google", "ConfirmTeeDevice",2) => "MEQCIC65mBMi9Vd5c9fZbMBbKsQYEZCEltasrAkOxi0UalENAiBvgT82Lk5EGnRmIxwXP5iix6T5jWmZOAn+i4Kkjgt9UA==".to_owned(),
        ("Google", "CreateWalletKey",_) => CREATE_KEY_ASSERTION.to_owned(),
        ("Google", "ConfirmWalletKey",1) => CONFIRM_KEY_ASSERTION.to_owned(),
        ("Google", "ConfirmWalletKey",2) => "MEQCIGAhEdUDoWkrWn0IKVYEq+XpdeXUizpWwgj9YUbKqqKJAiAgKIz5tZhM+5IyqzbpHGGYtsDcO7du3SGLo/m2WgG97Q==".to_owned(),
        ("Google", "ConfirmWalletKey",3) => CONFIRM_KEY_ASSERTION.to_owned(),
        ("Google", "Sign",_) => SIGN_ASSERTION.to_owned(),
        ("Google", "SignWithoutAssertion",_) => "MEQCIDa9Nx4ZPCTpo2S8rKm/U5gdkYbUQiwCnwydXGAa5WCRAiAse4MU24IJdv65Jspc3RzM0HU8q8EYnzqgi5yCV5FRBw==".to_owned(),
        ("Google", "RecoverWallet",_) => "MEUCIQDuVPMZ9anWCtRtlzW9xfqw3yAM/lQ2osksOIdR5ZEfZgIgSJyp0z/OwJ4UeV5u4C4UhwS7XhJjb/MVKO1kwyXnnUY=".to_owned(),
        ("Google", "ModifyPassword",_) => "MEUCIQCrnWdeuVoxSzkrHg4r3aFHeVOvWdCGDYWzlyZjHzSAbgIgJTYUZiL51zBXHkO+o8uUq55nVqHNIgvAprOChZG2pA0=".to_owned(),
        ("Apple", "ConfirmTeeDevice",_) => "".to_owned(),
        ("Apple", "CreateWalletKey",_) => "".to_owned(),
        ("Apple", "ConfirmWalletKey",_) => "".to_owned(),
        ("Apple", "Sign",_) => "".to_owned(),
        ("Apple", "SignWithoutAssertion",_) => "".to_owned(),
        ("Apple", "RecoverWallet",_) => "".to_owned(),
        ("Apple", "ModifyPassword",_) => "".to_owned(),
        _ => bail!("unknown message type"),
    };
    Ok(assertion)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .context("failed to build HTTP client")?;

    match cli.command {
        Command::RunBasic => run_basic(&client, &cli.base_url).await?,
    }

    Ok(())
}

async fn run_basic(client: &Client, base_url: &str) -> Result<()> {
    let platform = "Google".to_string();
    //1) register tee device
    let register_tee_device_payload = register_tee_device_payload();
    let attestation = generate_tee_attestation(&platform, &register_tee_device_payload, 1);
    let tee_request = TeeClientRegisterRequest {
        attestation,
        platform: platform.clone(),
        issued_at: ISSUED_AT,
        nonce: NONCE.to_string(),
        key_id: KEY_ID.to_string(),
        region: REGION.to_string(),
    };

    let tee_response = post_json(
        client,
        base_url,
        "/register_tee_device",
        &tee_request,
        "register_tee_device",
    )
    .await?;
    println!("tee_response: {:?}", tee_response);
    let register_data: RegisterTeeDeviceResponse =
        serde_json::from_value(extract_attested_data(&tee_response)?)?;
    let device_ciphertext = register_data.client_ciphertext;
    println!("{}", device_ciphertext);
    //由于每次device_ciphertext 都会变更，此处使用一个固定结果
    let device_ciphertext = FIX_DEVICE_CIPHERTEXT.to_owned();
    let confirm_tee_device_payload_str = confirm_tee_device_payload(&device_ciphertext);
    let device_confirmed_assertion =
        generate_tee_assertion(&platform, &confirm_tee_device_payload_str, 1)?;
    //
    //
    //2) create wallet key
    let create_wallet_key_payload = create_wallet_key_payload();
    let create_key_assertion = generate_tee_assertion(&platform, &create_wallet_key_payload, 1)?;
    let pwd_sig = sign_with_password(PASSWORD_SEED, &create_wallet_key_payload)?;
    let pwd_pubkey = password_pubkey(PASSWORD_SEED);
    println!(
        "pwd_pubkey={},\npwd_sig={},\ndata={}",
        pwd_pubkey, pwd_sig, create_wallet_key_payload
    );
    enclave_vault::model::verify_pwd_sig(&create_wallet_key_payload, &pwd_pubkey, &pwd_sig)?;
    println!("create_wallet_key_payload: {}", create_wallet_key_payload);
    let create_request = CreateWalletKeyRequest {
        issued_at: ISSUED_AT,
        nonce: NONCE.to_string(),
        key_id: KEY_ID.to_string(),
        region: REGION.to_string(),
        pwd_pubkey: pwd_pubkey.clone(),
        pwd_sig: pwd_sig.clone(),
        device_ciphertext: device_ciphertext.clone(),
        device_confirmed_assertion,
        bind_device_ciphertext: device_ciphertext.clone(),
        bind_device_confirmed_assertion: CONFIRM_DEVICE_ASSERTION.to_string(),
        create_key_assertion,
        master_key_bond_ciphertext: None,
        master_key_bond_confirmed_assertion: None,
    };

    let create_response = post_json(
        client,
        base_url,
        "/create_wallet_key",
        &create_request,
        "create_wallet_key",
    )
    .await?;
    println!("create_response: {:?}", create_response);
    let create_data: CreateWalletKeyResponse =
        serde_json::from_value(extract_attested_data(&create_response)?)?;
    // 这里的key_bond_ciphertext也是需要固定下来
    let key_bond_ciphertext = create_data.key_bond_ciphertext;
    let key_bond_ciphertext = FIX_KEY_BOND_CIPHERTEXT.to_string();
    let confirm_create_wallet_key_payload = confirm_wallet_key_payload(&key_bond_ciphertext);
    println!(
        "confirm_create_wallet_key_payload: {}",
        confirm_create_wallet_key_payload
    );
    let key_bond_confirmed_assertion =
        generate_tee_assertion(&platform, &confirm_create_wallet_key_payload, 1)?;

    //
    //
    //
    //3) sign
    let sign_payload_str = sign_payload(&PLACEHOLDER_MESSAGE.as_bytes().encode_bs64());
    let sign_assertion = generate_tee_assertion(&platform, &sign_payload_str, 1)?;
    let pwd_sig = sign_with_password(PASSWORD_SEED, &sign_payload_str)?;
    let sign_request: SignRequest = SignRequest {
        message: PLACEHOLDER_MESSAGE.as_bytes().encode_bs64(),
        issued_at: ISSUED_AT,
        nonce: NONCE.to_string(),
        region: REGION.to_string(),
        pwd_sig,
        key_bond_ciphertext: key_bond_ciphertext.to_string(),
        key_bond_confirmed_assertion: key_bond_confirmed_assertion.clone(),
        sign_assertion,
    };

    let sign_response = post_json(client, base_url, "/sign", &sign_request, "sign").await?;
    println!("sign_response: {:?}", sign_response);

    let sign_data: SignResponse = serde_json::from_value(extract_attested_data(&sign_response)?)?;
    let wallet_sign_sig = sign_data.sig;
    println!("wallet_sign_sig: {}", wallet_sign_sig);

    //4)    modify_password
    let new_pwd_pubkey = password_pubkey(NEW_PASSWORD_SEED);
    let modify_payload = modify_password_payload();
    println!("modify_payload: {}", modify_payload);
    let new_pwd_sig = sign_with_password(NEW_PASSWORD_SEED, &modify_payload)?;
    let modify_password_assertion = generate_tee_assertion(&platform, &modify_payload, 2)?;

    let key_bonds = vec![ConfirmedKeyBond {
        ciphertext: key_bond_ciphertext.clone(),
        confirmed_assertion: key_bond_confirmed_assertion.clone(),
    }];

    let modify_password_request = ModifyPasswordRequest {
        key_bonds: key_bonds.clone(),
        new_pwd_pubkey: new_pwd_pubkey,
        new_pwd_sig,
        assertion: modify_password_assertion,
        issued_at: ISSUED_AT,
        nonce: NONCE.to_string(),
        key_id: KEY_ID.to_string(),
        region: REGION.to_string(),
    };

    let modify_password_response = post_json(
        client,
        base_url,
        "/modify_password",
        &modify_password_request,
        "modify_password",
    )
    .await?;
    println!("modify_password_response: {:?}", modify_password_response);
    let new_key_bonds: ModifyPasswordResponse =
        serde_json::from_value(extract_attested_data(&modify_password_response)?)?;
    println!("new_key_bonds: {:?}", new_key_bonds);
    // 重新签名新的key_bond_ciphertext
    let new_key_bond_ciphertext = new_key_bonds.new_key_bonds[0].key_bond_ciphertext.clone();
    let confirm_create_wallet_key_payload = confirm_wallet_key_payload(&new_key_bond_ciphertext);
    let new_key_bond_confirmed_assertion =
        generate_tee_assertion(&platform, &confirm_create_wallet_key_payload, 2)?;

    //5) sign_without_assertion with new_password
    let sign_without_assertion_payload_str =
        sign_without_assertion_payload(&PLACEHOLDER_MESSAGE.as_bytes().encode_bs64());
    //let sign_assertion = generate_tee_assertion(&platform, &sign_without_assertion_payload_str, 1)?;
    let pwd_sig = sign_with_password(NEW_PASSWORD_SEED, &sign_without_assertion_payload_str)?;
    let sign_without_assertion_request = SignWithoutAssertionRequest {
        key_bond_ciphertext: new_key_bond_ciphertext.clone(),
        key_bond_confirmed_assertion: new_key_bond_confirmed_assertion.clone(),
        pwd_sig,
        //sign_assertion: sign_assertion,
        message: PLACEHOLDER_MESSAGE.as_bytes().encode_bs64(),
        issued_at: ISSUED_AT,
        nonce: NONCE.to_string(),
        region: REGION.to_string(),
    };

    let sign_without_assertion_response = post_json(
        client,
        base_url,
        "/sign_without_assertion",
        &sign_without_assertion_request,
        "sign_without_assertion",
    )
    .await?;
    println!(
        "sign_without_assertion_response: {:?}",
        sign_without_assertion_response
    );

    //6  recovre wallet
    //6.1）new device register
    let register_tee_device_payload = register_tee_device_payload2();
    let attestation = generate_tee_attestation(&platform, &register_tee_device_payload, 2);
    let tee_request = TeeClientRegisterRequest {
        attestation,
        platform: platform.clone(),
        issued_at: NEW_DEVICE_ISSUED_AT,
        nonce: NEW_DEVICE_NONCE.to_string(),
        key_id: KEY_ID.to_string(),
        region: REGION.to_string(),
    };

    let tee_response = post_json(
        client,
        base_url,
        "/register_tee_device",
        &tee_request,
        "register_tee_device",
    )
    .await?;
    println!("tee_response: {:?}", tee_response);
    let register_data: RegisterTeeDeviceResponse =
        serde_json::from_value(extract_attested_data(&tee_response)?)?;
    let new_device_ciphertext = register_data.client_ciphertext;
    println!("{}", device_ciphertext);
    //由于每次device_ciphertext 都会变更，此处使用一个固定结果
    let new_device_ciphertext = FIX_NEW_DEVICE_CIPHERTEXT.to_owned();
    let confirm_tee_device_payload_str = confirm_tee_device_payload(&device_ciphertext);
    println!("{}", confirm_tee_device_payload_str);
    let new_device_confirmed_assertion =
        generate_tee_assertion(&platform, &confirm_tee_device_payload_str, 2)?;
    //6.2) reovery wallet
    let recover_payload = recover_wallet_payload();
    println!("modify_payload: {}", modify_payload);
    let pwd_recover_sig = sign_with_password(NEW_PASSWORD_SEED, &recover_payload)?;
    let recover_assertion = generate_tee_assertion(&platform, &recover_payload, 1)?;

    let recover_wallet_request = RecoverWalletRequest {
        new_device_ciphertext: new_device_ciphertext.clone(),
        new_device_confirmed_assertion: new_device_confirmed_assertion.clone(),
        key_bonds: vec![ConfirmedKeyBond {
            ciphertext: new_key_bond_ciphertext.clone(),
            confirmed_assertion: new_key_bond_confirmed_assertion.clone(),
        }],
        pwd_sig: pwd_recover_sig.clone(),
        assertion: recover_assertion,
        issued_at: ISSUED_AT,
        nonce: NONCE.to_string(),
        key_id: KEY_ID.to_string(),
        region: REGION.to_string(),
    };

    let recover_wallet_response = post_json(
        client,
        base_url,
        "/recover_wallet",
        &recover_wallet_request,
        "recover_wallet",
    )
    .await?;
    println!("recover_wallet_response: {:?}", recover_wallet_response);
    //7) (option),  钱包恢复之后使用sign接口确认一下

    Ok(())
}

fn password_pubkey(password_seed: &str) -> String {
    let (_, pubkey) = ed25519::new_key_pair_by_seed(password_seed);
    pubkey.encode_bs58()
}

fn sign_with_password(password_seed: &str, payload: &str) -> Result<String> {
    let (prikey, _) = ed25519::new_key_pair_by_seed(password_seed);
    let sig = ed25519::sign(&prikey, payload.as_bytes())?;
    Ok(sig.encode_bs58())
}

async fn post_json<T: Serialize>(
    client: &Client,
    base_url: &str,
    path: &str,
    payload: &T,
    label: &str,
) -> Result<ApiResponse> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    let payload_json = serde_json::to_value(payload).context("failed to serialize request body")?;
    println!(
        "url: {},\n{} request:\n{}",
        &url,
        label,
        serde_json::to_string_pretty(&payload_json)?
    );

    let response = client
        .post(url.clone())
        .json(payload)
        .header("Content-Type", "application/json")
        .send()
        .await
        .with_context(|| format!("{} request failed", label))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .with_context(|| format!("{} response body read failed", label))?;

    println!("{} response status: {}", label, status);
    println!("{} response body:\n{}", label, body);

    if !status.is_success() {
        bail!("{} returned non-success status {}", label, status);
    }

    let parsed: ApiResponse = serde_json::from_str(&body)
        .with_context(|| format!("{} response JSON deserialize failed", label))?;
    if let Some(errors) = &parsed.errors {
        if !errors.is_empty() {
            bail!("{} returned business errors: {}", label, errors.join("; "));
        }
    }
    Ok(parsed)
}

fn extract_attestation(response: &ApiResponse) -> Result<String> {
    response
        .fields
        .get("attestation")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            response
                .fields
                .values()
                .find_map(Value::as_str)
                .map(str::to_owned)
        })
        .context("response did not contain any attestation string field")
}

fn extract_attested_data(response: &ApiResponse) -> Result<Value> {
    let attestation = extract_attestation(response)?;
    let attestation_doc = aws::parse_cose_sign1_view(&attestation.decode_hex()?)?;
    println!("{:#?}", attestation_doc);
    let payload = attestation_doc
        .payload
        .user_data
        .context("attestation payload did not contain user_data")?;
    let attested_json = serde_json::Value::from_str(&payload)?;
    attested_json
        .get("data")
        .cloned()
        .context("attested payload did not contain `data`")
}
