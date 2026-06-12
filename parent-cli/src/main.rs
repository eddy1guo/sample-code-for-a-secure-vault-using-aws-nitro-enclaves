use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use enclave_vault::credential::aws;
use enclave_vault::credential::common::sha256_bytes;
use enclave_vault::ed25519;
use enclave_vault::error::Error as EnclaveError;
use enclave_vault::model::ModifyPasswordResponse;
use enclave_vault::{
    codec::{
        bs58::EncodeBs58,
        bs64::EncodeBs64,
        hex::{DecodeHex, EncodeHex},
    },
    functions::now_millis,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEFAULT_BASE_URL: &str = "https://localhost:10001";
const REGION: &str = "ap-southeast-1";
const KEY_ID: &str = "mrk-794e2c0173cd4848849739bf393a76b5";
const PLACEHOLDER_MESSAGE: &str = "hello-wallet-sign";
const PASSWORD_SEED: &str = "123456";
const NEW_PASSWORD_SEED: &str = "223456";
const NONCE: &str = "1111";
const ISSUED_AT: i64 = 1779876890;
const NEW_DEVICE_NONCE: &str = "1111100";
const NEW_DEVICE_ISSUED_AT: i64 = 1779876990;
const GOOGLE_ATTESTATION: [&str; 5] = [
    "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",
];
const FIX_DEVICE_CIPHERTEXT: &str = "487684d23e88b5ee40aedcd3aa170971bf2bbf0605f2657114bfe9f35257194fd7d1d71b03c55b38aa829d0444aeb010bfed35443b5dcc9ac3a9ec77605e34b6a6753abb3d7860a9957a4a16a064bc39a1dc650018288b251ab7f1f3df9ad6f6cccc0e691b9196a97684ba8e266d1a29e2e2b8ce9335ecf9867798ba2dffba760b0fa5b7ce9891e83f825dd4f8387f38c4fb17d00c324e54223c0343920d9a61b2af49bcc83eaa97c8bedf2a0c9dbf2b5593bec6f05d8fdec3cec0affa5b695aa2bc4c44b0cb2c8bb692e50183a62e54f825adbdfc07d421087306b872957198a1d390f9aa2f74ee5b38628336584faa9bc19dbc2dfadbe913";
const FIX_NEW_DEVICE_CIPHERTEXT: &str = "c0b4bc5f5b3bc137bdeda5c8b40ce55de26bcb4484f97b64a71e32a508dde40e2e29cf3a42c1a9eca13d930fdc518710a7f1ecc193af2239cfe3449e18daf2b5c644f1907b85d80538205ea9e04ba6f6f078ae5e66fdb3f79fd4575040fbd2e15ed5542830282d0386dce37467de6d8f146f47b2ebb3ccafc53f9d7f9c94b1f61b94b57e70921083ce0b456380898bcb769846bd6e468229289fba2d68a23c574a449485d87a4a9fa156627933c931a64f7343a483f0da0dc30b55cc6e552dcc4445d4c8ce507d9a35924318b3c20f73b24b58d18a6908dc2ed1e5dfc4505da6b490917913d8245ab283550f397ff40f99b0290284b89a1c5a";

const FIX_KEY_BOND_CIPHERTEXT: &str = "035e5f0f261d42dc631d5591fdbd9fc1a421c37caeebfc0e7746859f60605bb7ec1f4c25cc11ef76c8ae5269ebfea337315986bd73669a3f9e2f63dd85150a3067483f79a3031a3eafb20db5cbd9943d17de3c254f55167aebf474b5ebd3c7b0a9a6e8de80290e89308459ac39095f4d8070b63620ba190c3ce3cd4ff8489dead67f666b1c8729a575630218f20be8553428542b6b4cc3ee3fd6dc2379fab803cead48b3c0d26a07d7139623e45dfd131ec2913f405bfef13edd77913e0efb8c87ff9a952d6a37d85cd6755db48d3c7f167d547ff9ef7a22c082647fb4728326f0ba52a2984815d01a1cb9a1bcb5d8d4b216ba655d43f3bc71a6e0602cfe431bda9cdbc31ba1105a76d531ae5b03db039d64a08d55b0d5a0a5408c81ed4bd3d5e89c55c7de12acacef6847c09fdebeaf13d5ba923fe21878337438f733af6085e97ecbde986fd7427f7e49fa446ed2f9e3bfc50d24c4f3432e5f3c57c0e1eb46a5f39b88df7998f13e536cef77e65e8682f3cfc02bac4fa436ce07b2f8ae92faaaf6a9cfa24b24d9491671f8c6702b3471b72427d427af3fc2a9f2828413b2e8c3acaf6ac28ff76fe1285161855acf8034b433c964bd020b111aa71b2dae6b8d7d9513f82de5bd367bfbff54a08a533b509e59aa5dfc6f54035d58c6f3f7a60574d347f5c4e5585491adb0ef7bf592a55bd235a8c4c3c7692ab37bb5b0b6a21d8f423aaed103cc011a65162bc66faca51e93cc3803a266661ecbe79ee394ba747ece36c330984a2265611dd669d8752e54729a0d2185b485f7f826a70e0ede8378d9fe2e8c4a2bc63965d3439b38a7d44091397c4bf5104b3aed2b12ec629ec3c276573ef91ecf121e212741bc807d7434d7996f";
const CONFIRM_DEVICE_ASSERTION: &str = "MEQCIExrRjnYINGXb0L+9uFV7GfhPhNPorFpBrXo7Q8CZYh2AiA96eoA3+km/HFtRF5NLalqsIjFKYvbDzV7tPRVAmxnrw==";
const CREATE_KEY_ASSERTION: &str = "MEUCIQDkUENQfUm7y4fk+M1Xml2LpCtox3m09reCFClLidiOAwIgOKwT/RR5uwYvHxd9uWtfCAVIKbact5vD7YcA6tqZiXI=";
const CONFIRM_KEY_ASSERTION: &str = "MEQCICANP91P4UZiHscz3YHLqj8PgZixAg1YjI109ESAVd8HAiBIo+lFYZlfEOv9WtFyLs23kBkxSqUNkSJXM02e5DbxSA==";
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
    sign_without_assertion_payload_with_params(message, ISSUED_AT, NONCE)
}

pub fn sign_without_assertion_payload_with_params(
    message: &str,
    issued_at: i64,
    nonce: &str,
) -> String {
    format!(
        "{{\"type\":\"SignWithoutAssertion\",\"message\":\"{}\",\"issued_at\":{},\"nonce\":\"{}\"}}",
        message, issued_at, nonce
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
    VerifyWalletLockSleep,
    RunRootSecret {
        #[arg(long, default_value = KEY_ID)]
        key_id: String,
        #[arg(long, default_value = REGION)]
        region: String,
    },
    GenerateRootSecretCiphertext {
        #[arg(long, default_value = KEY_ID)]
        key_id: String,
        #[arg(long, default_value = REGION)]
        region: String,
    },
    InjectRootSecretCiphertext {
        #[arg(long)]
        root_secret_ciphertext: String,
        #[arg(long, default_value = REGION)]
        region: String,
    },
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
    user_id: u64,
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
    current_pwd_sig: String,
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
    tee_device_pubkey: String,
}

#[derive(Debug, Serialize)]
struct GenerateRootSecretCiphertextRequest {
    key_id: String,
    region: String,
}

#[derive(Debug, Deserialize)]
struct GenerateRootSecretCiphertextResponse {
    root_secret_ciphertext: String,
}

#[derive(Debug, Serialize)]
struct InjectRootSecretCiphertextRequest {
    root_secret_ciphertext: String,
    region: String,
}

#[derive(Debug, Deserialize)]
struct InjectRootSecretCiphertextResponse {
    injected: bool,
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
        ("Google", "ConfirmTeeDevice",2) => "MEUCIG7uLUEnW0W/XCOzkGBdEQMgNJDDliHwnUm++/+rbqUFAiEA8EdISVrtUfzgJVSPaBfslEFm3mnkX91fUVj2XzQWZuA=".to_owned(),
        ("Google", "CreateWalletKey",_) => CREATE_KEY_ASSERTION.to_owned(),
        ("Google", "ConfirmWalletKey",1) => CONFIRM_KEY_ASSERTION.to_owned(),
        ("Google", "ConfirmWalletKey",2) => "MEUCIE7GS41xLuVsh/BOx1S53SIopQ09kzmuWVHVOAUuU4IiAiEA32nFZc73Z5+oYgx9aYs+fHcdouQsWWIY5Kcxm0chKcI=".to_owned(),
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
        Command::VerifyWalletLockSleep => {
            run_verify_wallet_lock_sleep(&client, &cli.base_url).await?
        }
        Command::RunRootSecret { key_id, region } => {
            run_root_secret(&client, &cli.base_url, &key_id, &region).await?
        }
        Command::GenerateRootSecretCiphertext { key_id, region } => {
            let root_secret_ciphertext =
                generate_root_secret_ciphertext_example(&client, &cli.base_url, &key_id, &region)
                    .await?;
            println!("root_secret_ciphertext: {}", root_secret_ciphertext);
        }
        Command::InjectRootSecretCiphertext {
            root_secret_ciphertext,
            region,
        } => {
            inject_root_secret_ciphertext_example(
                &client,
                &cli.base_url,
                &root_secret_ciphertext,
                &region,
            )
            .await?;
        }
    }

    Ok(())
}

async fn run_root_secret(
    client: &Client,
    base_url: &str,
    key_id: &str,
    region: &str,
) -> Result<()> {
    let root_secret_ciphertext =
        generate_root_secret_ciphertext_example(client, base_url, key_id, region).await?;
    println!(
        "generated root_secret_ciphertext: {}",
        root_secret_ciphertext
    );

    inject_root_secret_ciphertext_example(client, base_url, &root_secret_ciphertext, region).await
}

async fn generate_root_secret_ciphertext_example(
    client: &Client,
    base_url: &str,
    key_id: &str,
    region: &str,
) -> Result<String> {
    let request = GenerateRootSecretCiphertextRequest {
        key_id: key_id.to_string(),
        region: region.to_string(),
    };
    let response = post_json(
        client,
        base_url,
        "/generate_root_secret_ciphertext",
        &request,
        "generate_root_secret_ciphertext",
    )
    .await?;
    let data: GenerateRootSecretCiphertextResponse =
        serde_json::from_value(extract_attested_data(&response)?)?;
    Ok(data.root_secret_ciphertext)
}

async fn inject_root_secret_ciphertext_example(
    client: &Client,
    base_url: &str,
    root_secret_ciphertext: &str,
    region: &str,
) -> Result<()> {
    let request = InjectRootSecretCiphertextRequest {
        root_secret_ciphertext: root_secret_ciphertext.to_string(),
        region: region.to_string(),
    };
    let response = post_json(
        client,
        base_url,
        "/inject_root_secret_ciphertext",
        &request,
        "inject_root_secret_ciphertext",
    )
    .await?;
    let data: InjectRootSecretCiphertextResponse =
        serde_json::from_value(extract_attested_data(&response)?)?;
    if !data.injected {
        bail!("inject_root_secret_ciphertext returned injected=false");
    }
    println!("inject_root_secret_ciphertext succeeded");
    Ok(())
}

async fn prepare_sign_without_assertion_fixture(
    client: &Client,
    base_url: &str,
) -> Result<(String, String)> {
    run_root_secret(client, base_url, KEY_ID, REGION).await?;

    let platform = "Google".to_string();
    let register_payload = register_tee_device_payload();
    let attestation = generate_tee_attestation(&platform, &register_payload, 1);
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
        "register_tee_device_for_wallet_lock",
    )
    .await?;
    let register_data: RegisterTeeDeviceResponse =
        serde_json::from_value(extract_attested_data(&tee_response)?)?;
    let device_ciphertext = register_data.client_ciphertext;
    let confirm_tee_device_payload_str = confirm_tee_device_payload(&device_ciphertext);
    let device_confirmed_assertion =
        generate_tee_assertion(&platform, &confirm_tee_device_payload_str, 1)?;

    let create_payload = create_wallet_key_payload();
    let create_key_assertion = generate_tee_assertion(&platform, &create_payload, 1)?;
    let pwd_sig = sign_with_password(PASSWORD_SEED, &create_payload)?;
    let pwd_pubkey = password_pubkey(PASSWORD_SEED);
    let create_request = CreateWalletKeyRequest {
        user_id: now_millis() as u64,
        issued_at: ISSUED_AT,
        nonce: NONCE.to_string(),
        key_id: KEY_ID.to_string(),
        region: REGION.to_string(),
        pwd_pubkey,
        pwd_sig,
        device_ciphertext: device_ciphertext.clone(),
        device_confirmed_assertion: device_confirmed_assertion.clone(),
        bind_device_ciphertext: device_ciphertext.clone(),
        bind_device_confirmed_assertion: device_confirmed_assertion,
        create_key_assertion,
        master_key_bond_ciphertext: None,
        master_key_bond_confirmed_assertion: None,
    };

    let create_response = post_json(
        client,
        base_url,
        "/create_wallet_key",
        &create_request,
        "create_wallet_key_for_wallet_lock",
    )
    .await?;
    let create_data: CreateWalletKeyResponse =
        serde_json::from_value(extract_attested_data(&create_response)?)?;
    let key_bond_ciphertext = create_data.key_bond_ciphertext;
    let confirm_payload = confirm_wallet_key_payload(&key_bond_ciphertext);
    let key_bond_confirmed_assertion = generate_tee_assertion(&platform, &confirm_payload, 1)?;

    Ok((key_bond_ciphertext, key_bond_confirmed_assertion))
}

async fn expect_wrong_password_result(
    client: &Client,
    base_url: &str,
    key_bond_ciphertext: &str,
    key_bond_confirmed_assertion: &str,
    label: &str,
    sleep_secs: u64,
    expected_error: EnclaveError,
) -> Result<()> {
    if sleep_secs > 0 {
        println!("sleep {} seconds before {}", sleep_secs, label);
        tokio::time::sleep(std::time::Duration::from_secs(sleep_secs)).await;
    }

    let nonce = format!("{}-{}", label, now_millis());
    let payload = sign_without_assertion_payload_with_params(
        &PLACEHOLDER_MESSAGE.as_bytes().encode_bs64(),
        ISSUED_AT,
        &nonce,
    );
    let request = SignWithoutAssertionRequest {
        key_bond_ciphertext: key_bond_ciphertext.to_string(),
        key_bond_confirmed_assertion: key_bond_confirmed_assertion.to_string(),
        pwd_sig: sign_with_password(NEW_PASSWORD_SEED, &payload)?,
        message: PLACEHOLDER_MESSAGE.as_bytes().encode_bs64(),
        issued_at: ISSUED_AT,
        nonce,
        region: REGION.to_string(),
    };

    let response = post_json_allow_business_errors(
        client,
        base_url,
        "/sign_without_assertion",
        &request,
        label,
    )
    .await?;
    expect_business_error(
        &response,
        expected_error.code(),
        &expected_error.to_string(),
    )?;
    println!("{} => {}", label, expected_error);
    Ok(())
}

async fn run_verify_wallet_lock_sleep(client: &Client, base_url: &str) -> Result<()> {
    // Tier 1: 3 minutes / 2 failures, third request becomes locked.
    let (key_bond_ciphertext, key_bond_confirmed_assertion) =
        prepare_sign_without_assertion_fixture(client, base_url).await?;
    expect_wrong_password_result(
        client,
        base_url,
        &key_bond_ciphertext,
        &key_bond_confirmed_assertion,
        "debug_tier1_attempt_1_now",
        0,
        EnclaveError::PwdSigVerifyFailed,
    )
    .await?;
    expect_wrong_password_result(
        client,
        base_url,
        &key_bond_ciphertext,
        &key_bond_confirmed_assertion,
        "debug_tier1_attempt_2_after_1m",
        60,
        EnclaveError::PwdSigVerifyFailed,
    )
    .await?;
    expect_wrong_password_result(
        client,
        base_url,
        &key_bond_ciphertext,
        &key_bond_confirmed_assertion,
        "debug_tier1_attempt_3_after_2m",
        60,
        EnclaveError::WalletIsLocked,
    )
    .await?;

    // Tier 2: 6 minutes / 3 failures. We keep attempts outside the 3-minute
    // lock window until the third failure, then verify the next request is locked.
    let (key_bond_ciphertext, key_bond_confirmed_assertion) =
        prepare_sign_without_assertion_fixture(client, base_url).await?;
    expect_wrong_password_result(
        client,
        base_url,
        &key_bond_ciphertext,
        &key_bond_confirmed_assertion,
        "debug_tier2_attempt_1_now",
        0,
        EnclaveError::PwdSigVerifyFailed,
    )
    .await?;
    expect_wrong_password_result(
        client,
        base_url,
        &key_bond_ciphertext,
        &key_bond_confirmed_assertion,
        "debug_tier2_attempt_2_after_181s",
        181,
        EnclaveError::PwdSigVerifyFailed,
    )
    .await?;
    expect_wrong_password_result(
        client,
        base_url,
        &key_bond_ciphertext,
        &key_bond_confirmed_assertion,
        "debug_tier2_attempt_3_after_359s",
        178,
        EnclaveError::PwdSigVerifyFailed,
    )
    .await?;
    expect_wrong_password_result(
        client,
        base_url,
        &key_bond_ciphertext,
        &key_bond_confirmed_assertion,
        "debug_tier2_attempt_4_after_360s",
        1,
        EnclaveError::WalletIsLocked,
    )
    .await?;

    // Tier 3: 9 minutes / 4 failures. Same idea, but stretch the timeline so
    // the fourth failure is the one that arms the lock state.
    let (key_bond_ciphertext, key_bond_confirmed_assertion) =
        prepare_sign_without_assertion_fixture(client, base_url).await?;
    expect_wrong_password_result(
        client,
        base_url,
        &key_bond_ciphertext,
        &key_bond_confirmed_assertion,
        "debug_tier3_attempt_1_now",
        0,
        EnclaveError::PwdSigVerifyFailed,
    )
    .await?;
    expect_wrong_password_result(
        client,
        base_url,
        &key_bond_ciphertext,
        &key_bond_confirmed_assertion,
        "debug_tier3_attempt_2_after_181s",
        181,
        EnclaveError::PwdSigVerifyFailed,
    )
    .await?;
    expect_wrong_password_result(
        client,
        base_url,
        &key_bond_ciphertext,
        &key_bond_confirmed_assertion,
        "debug_tier3_attempt_3_after_359s",
        178,
        EnclaveError::PwdSigVerifyFailed,
    )
    .await?;
    expect_wrong_password_result(
        client,
        base_url,
        &key_bond_ciphertext,
        &key_bond_confirmed_assertion,
        "debug_tier3_attempt_4_after_539s",
        180,
        EnclaveError::PwdSigVerifyFailed,
    )
    .await?;
    expect_wrong_password_result(
        client,
        base_url,
        &key_bond_ciphertext,
        &key_bond_confirmed_assertion,
        "debug_tier3_attempt_5_after_540s",
        1,
        EnclaveError::WalletIsLocked,
    )
    .await?;

    println!(
        "debug tier 4 (12 minutes / 8 failures) is not independently reachable via live requests because shorter debug windows lock first"
    );
    println!("wallet lock debug-window verification finished");
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
        user_id: now_millis() as u64,
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
    let _key_bond_ciphertext = create_data.key_bond_ciphertext;
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
    let current_pwd_sig = sign_with_password(PASSWORD_SEED, &modify_payload)?;
    let new_pwd_sig = sign_with_password(NEW_PASSWORD_SEED, &modify_payload)?;
    let modify_password_assertion = generate_tee_assertion(&platform, &modify_payload, 2)?;

    let key_bonds = vec![ConfirmedKeyBond {
        ciphertext: key_bond_ciphertext.clone(),
        confirmed_assertion: key_bond_confirmed_assertion.clone(),
    }];

    let modify_password_request = ModifyPasswordRequest {
        key_bonds: key_bonds.clone(),
        current_pwd_sig,
        new_pwd_pubkey,
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
    println!("{}_new_key_bonds: {:?}", line!(), new_key_bonds);
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
    println!("file={},line={}", file!(), line!());
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
    println!("file={},line={}", file!(), line!());
    let sign_without_assertion_data: SignResponse =
        serde_json::from_value(extract_attested_data(&sign_without_assertion_response)?)?;
    println!(
        "sign_without_assertion_sig: {}",
        sign_without_assertion_data.sig
    );
    println!("file={},line={}", file!(), line!());

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
    println!("file={},line={}", file!(), line!());
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
    println!("{}", new_device_ciphertext);
    //由于每次device_ciphertext 都会变更，此处使用一个固定结果
    let new_device_ciphertext = FIX_NEW_DEVICE_CIPHERTEXT.to_owned();
    let confirm_tee_device_payload_str = confirm_tee_device_payload(&new_device_ciphertext);
    println!("{}", confirm_tee_device_payload_str);
    let new_device_confirmed_assertion =
        generate_tee_assertion(&platform, &confirm_tee_device_payload_str, 2)?;
    //6.2) reovery wallet
    let recover_payload = recover_wallet_payload();
    println!("recover_payload: {}", recover_payload);
    let pwd_recover_sig = sign_with_password(NEW_PASSWORD_SEED, &recover_payload)?;
    let recover_assertion = generate_tee_assertion(&platform, &recover_payload, 1)?;

    println!("now: {}", now_millis());
    let recover_wallet_request = RecoverWalletRequest {
        new_device_ciphertext: new_device_ciphertext.clone(),
        new_device_confirmed_assertion: new_device_confirmed_assertion.clone(),
        // Keep three entries here to exercise the large-response recovery path.
        key_bonds: vec![
            ConfirmedKeyBond {
                ciphertext: new_key_bond_ciphertext.clone(),
                confirmed_assertion: new_key_bond_confirmed_assertion.clone(),
            };
            3
        ],
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
    println!("now: {}", now_millis());
    println!("recover_wallet_response: {:?}", recover_wallet_response);
    let recover_wallet_data: ModifyPasswordResponse =
        serde_json::from_value(extract_attested_data(&recover_wallet_response)?)?;
    println!("recover_wallet_data: {:?}", recover_wallet_data);
    //7) sign_without_assertion wrong password lockout check
    let wrong_attempt_nonce_1 = "wrong-sign-without-assertion-1";
    let wrong_attempt_payload_1 = sign_without_assertion_payload_with_params(
        &PLACEHOLDER_MESSAGE.as_bytes().encode_bs64(),
        ISSUED_AT,
        wrong_attempt_nonce_1,
    );
    let wrong_attempt_request_1 = SignWithoutAssertionRequest {
        key_bond_ciphertext: new_key_bond_ciphertext.clone(),
        key_bond_confirmed_assertion: new_key_bond_confirmed_assertion.clone(),
        pwd_sig: sign_with_password(PASSWORD_SEED, &wrong_attempt_payload_1)?,
        message: PLACEHOLDER_MESSAGE.as_bytes().encode_bs64(),
        issued_at: ISSUED_AT,
        nonce: wrong_attempt_nonce_1.to_string(),
        region: REGION.to_string(),
    };
    let wrong_attempt_response_1 = post_json_allow_business_errors(
        client,
        base_url,
        "/sign_without_assertion",
        &wrong_attempt_request_1,
        "sign_without_assertion_wrong_pwd_attempt_1",
    )
    .await?;
    expect_business_error(
        &wrong_attempt_response_1,
        EnclaveError::PwdSigVerifyFailed.code(),
        &EnclaveError::PwdSigVerifyFailed.to_string(),
    )?;
    println!("file={},line={}", file!(), line!());
    let wrong_attempt_nonce_2 = "wrong-sign-without-assertion-2";
    let wrong_attempt_payload_2 = sign_without_assertion_payload_with_params(
        &PLACEHOLDER_MESSAGE.as_bytes().encode_bs64(),
        ISSUED_AT,
        wrong_attempt_nonce_2,
    );
    let wrong_attempt_request_2 = SignWithoutAssertionRequest {
        key_bond_ciphertext: new_key_bond_ciphertext.clone(),
        key_bond_confirmed_assertion: new_key_bond_confirmed_assertion.clone(),
        pwd_sig: sign_with_password(PASSWORD_SEED, &wrong_attempt_payload_2)?,
        message: PLACEHOLDER_MESSAGE.as_bytes().encode_bs64(),
        issued_at: ISSUED_AT,
        nonce: wrong_attempt_nonce_2.to_string(),
        region: REGION.to_string(),
    };
    println!("file={},line={}", file!(), line!());
    let wrong_attempt_response_2 = post_json_allow_business_errors(
        client,
        base_url,
        "/sign_without_assertion",
        &wrong_attempt_request_2,
        "sign_without_assertion_wrong_pwd_attempt_2",
    )
    .await?;
    println!("file={},line={}", file!(), line!());
    expect_business_error(
        &wrong_attempt_response_2,
        EnclaveError::PwdSigVerifyFailed.code(),
        &EnclaveError::PwdSigVerifyFailed.to_string(),
    )?;
    let wrong_attempt_nonce_3 = "wrong-sign-without-assertion-3";
    let wrong_attempt_payload_3 = sign_without_assertion_payload_with_params(
        &PLACEHOLDER_MESSAGE.as_bytes().encode_bs64(),
        ISSUED_AT,
        wrong_attempt_nonce_3,
    );
    let wrong_attempt_request_3 = SignWithoutAssertionRequest {
        key_bond_ciphertext: new_key_bond_ciphertext.clone(),
        key_bond_confirmed_assertion: new_key_bond_confirmed_assertion.clone(),
        pwd_sig: sign_with_password(PASSWORD_SEED, &wrong_attempt_payload_3)?,
        message: PLACEHOLDER_MESSAGE.as_bytes().encode_bs64(),
        issued_at: ISSUED_AT,
        nonce: wrong_attempt_nonce_3.to_string(),
        region: REGION.to_string(),
    };
    let wrong_attempt_response_3 = post_json_allow_business_errors(
        client,
        base_url,
        "/sign_without_assertion",
        &wrong_attempt_request_3,
        "sign_without_assertion_wrong_pwd_attempt_3",
    )
    .await?;
    expect_business_error(
        &wrong_attempt_response_3,
        EnclaveError::WalletIsLocked.code(),
        &EnclaveError::WalletIsLocked.to_string(),
    )?;
    println!("sign_without_assertion wrong password lockout verified");
    println!("everything is done");
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
    let parsed = send_json_request(client, base_url, path, payload, label).await?;
    if let Some(errors) = &parsed.errors
        && !errors.is_empty() {
            bail!("{} returned business errors: {}", label, errors.join("; "));
        }
    Ok(parsed)
}

async fn post_json_allow_business_errors<T: Serialize>(
    client: &Client,
    base_url: &str,
    path: &str,
    payload: &T,
    label: &str,
) -> Result<ApiResponse> {
    send_json_request(client, base_url, path, payload, label).await
}

async fn send_json_request<T: Serialize>(
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
    let data = response
        .fields
        .get("data")
        .cloned()
        .context("response did not contain `data` field")?;
    println!("data={}", data);
    let attestation = extract_attestation(response)?;
    let attestation_doc = aws::parse_cose_sign1_view(&attestation.decode_hex()?)?;
    println!("{:#?}", attestation_doc);
    let payload_digest = attestation_doc
        .payload
        .user_data
        .context("attestation payload did not contain user_data")?;
    let actual_digest = sha256_bytes(data.to_string().as_bytes()).encode_hex();
    if payload_digest != actual_digest {
        bail!("attestation payload digest mismatch")
    }
    Ok(data)
}

fn expect_business_error(
    response: &ApiResponse,
    expected_code: u32,
    expected_msg: &str,
) -> Result<()> {
    let error = response
        .errors
        .as_ref()
        .and_then(|errors| errors.first())
        .context("response did not contain any business error")?;
    let error_json: Value =
        serde_json::from_str(error).context("business error was not valid json")?;
    let actual_code = error_json
        .get("code")
        .and_then(Value::as_u64)
        .context("business error did not contain numeric code")?;
    let actual_msg = error_json
        .get("msg")
        .and_then(Value::as_str)
        .context("business error did not contain msg")?;

    if actual_code != u64::from(expected_code) || actual_msg != expected_msg {
        bail!(
            "unexpected business error: expected code={}, msg={}, actual code={}, msg={}",
            expected_code,
            expected_msg,
            actual_code,
            actual_msg
        );
    }

    Ok(())
}
