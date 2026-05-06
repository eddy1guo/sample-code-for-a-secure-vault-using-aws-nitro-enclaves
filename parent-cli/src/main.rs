use std::str::FromStr;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use enclave_vault::codec::hex::DecodeHex;
use enclave_vault::credential::aws;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEFAULT_BASE_URL: &str = "https://localhost:10001";
const REGION: &str = "ap-southeast-1";
const KEY_ID: &str = "mrk-794e2c0173cd4848849739bf393a76b5";
const NONCE: &str = "1111";
const ISSUE_AT: u64 = 1777519926136;
const PLACEHOLDER_SIG: &str = "xxx";
const PLACEHOLDER_MESSAGE: &str = "hello-wallet-sign";
const APPLE_KEY_ID: &str = "LnxoVdHGe+HnCcwS7FCWJecITXf2KlJBoHO7/Jr4DFI=";

//todo:  跑一个 安卓的case
const APPLE_ATTESTATION_DOC: &str =
    include_str!("../../enclave/src/credential/testdata/ios_real_world_attestation_object.txt");

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
    attestation_doc: String,
    platform: String,
    issue_at: u64,
    nonce: String,
    key_id: String,
    region: String,
}

#[derive(Debug, Serialize)]
struct CreateWalletKeyRequest {
    verified_client: String,
    sig: String,
    issue_at: u64,
    nonce: String,
    key_id: String,
    region: String,
}

#[derive(Debug, Serialize)]
struct WalletSignRequest {
    verified_wallet_key: String,
    sig: String,
    message: String,
    issue_at: u64,
    nonce: String,
    region: String,
}

#[derive(Debug, Deserialize)]
struct ApiResponse {
    fields: std::collections::BTreeMap<String, Value>,
    #[serde(default)]
    errors: Option<Vec<String>>,
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
    let tee_request = TeeClientRegisterRequest {
        attestation_doc: APPLE_ATTESTATION_DOC.to_string(),
        platform: "Apple".to_string(),
        issue_at: ISSUE_AT,
        nonce: NONCE.to_string(),
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
    let register_doc_str = extract_string_field(&tee_response, "verified_client")
        .or_else(|_| extract_first_string_value(&tee_response))
        .context("tee_client_register did not return a usable verified_client value")?;
    let register_doc = aws::parse_cose_sign1_view(&register_doc_str.decode_hex()?)?;
    let verified_client_str = register_doc.payload.user_data.unwrap();
    let verified_client = serde_json::Value::from_str(&verified_client_str)?;
    //todo: 这里的json嵌套不应该过多
    //let verified_client = verified_client["tee_client"].to_string();
    let verified_client: String =
        serde_json::from_value(verified_client["tee_client"].clone()).unwrap_or_default();

    let create_request = CreateWalletKeyRequest {
        verified_client,
        sig: PLACEHOLDER_SIG.to_string(),
        issue_at: ISSUE_AT,
        nonce: NONCE.to_string(),
        key_id: KEY_ID.to_string(),
        region: REGION.to_string(),
    };

    let create_response = post_json(
        client,
        base_url,
        "/create_wallet_key",
        &create_request,
        "create_wallet_key",
    )
    .await?;
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
    let verified_wallet_key: String =
        serde_json::from_value(verified_wallet_key["prikey"].clone()).unwrap_or_default();

    let sign_request = WalletSignRequest {
        verified_wallet_key,
        sig: PLACEHOLDER_SIG.to_string(),
        message: PLACEHOLDER_MESSAGE.to_string(),
        issue_at: ISSUE_AT,
        nonce: NONCE.to_string(),
        region: REGION.to_string(),
    };

    let sign_response = post_json(
        client,
        base_url,
        "/wallet_sign",
        &sign_request,
        "wallet_sign",
    )
    .await?;

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
