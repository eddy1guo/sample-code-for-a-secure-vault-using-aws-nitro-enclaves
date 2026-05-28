use std::str::FromStr;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use enclave_vault::codec::{bs64::EncodeBs64, hex::DecodeHex};
use enclave_vault::credential::common::Usage;
use enclave_vault::credential::{attestation, aws};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const DEFAULT_BASE_URL: &str = "https://localhost:10001";
const REGION: &str = "ap-southeast-1";
const KEY_ID: &str = "mrk-794e2c0173cd4848849739bf393a76b5";
const NONCE: &str = "1111";
const ISSUED_AT: i64 = 1777519926;
const PLACEHOLDER_SIG: &str = "xxxxxxxxxxxx";
const PLACEHOLDER_MESSAGE: &str = "hello-wallet-sign";
const APPLE_KEY_ID: &str = "LnxoVdHGe+HnCcwS7FCWJecITXf2KlJBoHO7/Jr4DFI=";

//todo:  跑一个 安卓的case
const APPLE_ATTESTATION_DOC: &str =
    include_str!("../../enclave/src/credential/testdata/ios_real_world_attestation_object.txt");

//    {"type":"TeeClientRegister","issued_at":1779876890,"nonce":"1111"}
const GOOGLE_NONCE: &str = "1111";
const GOOGLE_ISSUED_AT: i64 = 1779876890;
const GOOGLE_ATTESTATION: [&str; 5] = [
    "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",
];
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
    pwd_pubkey: String,
    pwd_sig: String,
    create_key_assertion: String,
    issued_at: i64,
    nonce: String,
    key_id: String,
    region: String,
}

#[derive(Debug, Serialize)]
struct WalletSignRequest {
    key_bond_ciphertext: String,
    key_bond_confirmed_assertion: String,
    pwd_sig: String,
    sign_assertion: String,
    message: String,
    issued_at: i64,
    nonce: String,
    region: String,
}

#[derive(Debug, Deserialize)]
struct ApiResponse {
    fields: std::collections::BTreeMap<String, Value>,
    #[serde(default)]
    errors: Option<Vec<String>>,
}

use enclave_vault::credential::attestation::apple::RealWorldSample;

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
    // let sample: RealWorldSample = serde_json::from_str(APPLE_ATTESTATION_DOC)?;
    // let tee_request = TeeClientRegisterRequest {
    //     attestation: vec![sample.attestation_object_base64],
    //     platform: "Apple".to_string(),
    //     issued_at: ISSUED_AT,
    //     nonce: NONCE.to_string(),
    //     key_id: KEY_ID.to_string(),
    //     region: REGION.to_string(),
    // };

    let attestation = GOOGLE_ATTESTATION.iter().map(|x| x.to_string()).collect();
    let tee_request = TeeClientRegisterRequest {
        attestation,
        platform: "Google".to_string(),
        issued_at: GOOGLE_ISSUED_AT,
        nonce: GOOGLE_NONCE.to_string(),
        key_id: KEY_ID.to_string(),
        region: REGION.to_string(),
    };

    let tee_response = post_json(
        client,
        base_url,
        "/tee_client_register",
        &tee_request,
        "tee_client_register",
    )
    .await?;
    println!("tee_response: {:?}", tee_response);
    let register_doc_str = extract_string_field(&tee_response, "verified_client")
        .or_else(|_| extract_first_string_value(&tee_response))
        .context("tee_client_register did not return a usable verified_client value")?;
    let register_doc = aws::parse_cose_sign1_view(&register_doc_str.decode_hex()?)?;
    let verified_client_str = register_doc.payload.user_data.unwrap();
    let verified_client = serde_json::Value::from_str(&verified_client_str)?;
    //todo: 这里的json嵌套不应该过多
    //let verified_client = verified_client["tee_client"].to_string();
    let device_ciphertext: String =
        serde_json::from_value(verified_client["tee_client"].clone()).unwrap_or_default();

    let create_request = CreateWalletKeyRequest {
        issued_at: ISSUED_AT,
        nonce: NONCE.to_string(),
        key_id: KEY_ID.to_string(),
        region: REGION.to_string(),
        pwd_pubkey: "xxxxxxxx".to_string(),
        pwd_sig: "xxxxxxxx".to_string(),
        device_ciphertext: device_ciphertext,
        device_confirmed_assertion: PLACEHOLDER_SIG.to_string(),
        create_key_assertion: PLACEHOLDER_SIG.to_string(),
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

    let create_wallet_key_doc_str = extract_string_field(&create_response, "verified_wallet_key")
        .or_else(|_| extract_string_field(&create_response, "encrypted_wallet_key"))
        .or_else(|_| extract_first_string_value(&create_response))
        .context("create_wallet_key did not return a usable verified_wallet_key value")?;

    let create_wallet_key_doc =
        aws::parse_cose_sign1_view(&create_wallet_key_doc_str.decode_hex()?)?;
    println!("create_wallet_key_doc: {:?}", create_wallet_key_doc);
    let verified_wallet_key_str = create_wallet_key_doc.payload.user_data.unwrap();
    let verified_wallet_key = serde_json::Value::from_str(&verified_wallet_key_str)?;
    //todo: 这里的json嵌套不应该过多
    //let verified_client = verified_client["tee_client"].to_string();
    let key_bond_ciphertext: String =
        serde_json::from_value(verified_wallet_key["prikey"].clone()).unwrap_or_default();

    let sign_request: WalletSignRequest = WalletSignRequest {
        message: PLACEHOLDER_MESSAGE.as_bytes().encode_bs64(),
        issued_at: ISSUED_AT,
        nonce: NONCE.to_string(),
        region: REGION.to_string(),
        pwd_sig: PLACEHOLDER_SIG.to_string(),
        key_bond_ciphertext: key_bond_ciphertext,
        key_bond_confirmed_assertion: PLACEHOLDER_SIG.to_string(),
        sign_assertion: PLACEHOLDER_SIG.to_string(),
    };

    let sign_response = post_json(
        client,
        base_url,
        "/wallet_sign",
        &sign_request,
        "wallet_sign",
    )
    .await?;
    println!("sign_response: {:?}", sign_response);

    let sign_response_doc_str = extract_first_string_value(&sign_response)
        .context("sign_response_doc_str did not return a usable sign_response_doc_str value")?;

    let wallet_sign_doc = aws::parse_cose_sign1_view(&sign_response_doc_str.decode_hex()?)?;
    println!("create_wallet_key_doc: {:?}", wallet_sign_doc);
    let wallet_sign_str = wallet_sign_doc.payload.user_data.unwrap();
    let wallet_sign_res = serde_json::Value::from_str(&wallet_sign_str)?;
    //todo: 这里的json嵌套不应该过多
    //let verified_client = verified_client["tee_client"].to_string();
    let wallet_sign_sig: String = serde_json::from_value(wallet_sign_res["sig"].clone()).unwrap();
    println!("wallet_sign_sig: {}", wallet_sign_sig);
    Ok(())
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

fn extract_string_field(response: &ApiResponse, key: &str) -> Result<String> {
    response
        .fields
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .with_context(|| format!("missing string field `{}` in response", key))
}

fn extract_first_string_value(response: &ApiResponse) -> Result<String> {
    response
        .fields
        .values()
        .find_map(Value::as_str)
        .map(str::to_owned)
        .context("response did not contain any string field")
}
