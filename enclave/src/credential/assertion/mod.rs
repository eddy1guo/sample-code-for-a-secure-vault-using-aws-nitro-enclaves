pub mod apple;
pub mod google;

use serde_json::json;

use crate::{
    codec::{
        bs64::{DecodeBs64, EncodeBs64},
        hex::DecodeHex,
    },
    credential::common::{Platform, TeeClient, Usage, sha256_bytes},
};

pub fn verify_attested(
    platform: Platform,
    app_id: &str,
    assertion_object_base64: &str,
    pubkey_base64: &str,
    issued_at: u64,
    nonce: &str,
    usage: Usage,
    previous_counter: Option<u32>,
) -> anyhow::Result<Option<u32>> {
    let message = json!({
        "type": usage,
        "issued_at": issued_at,
        "nonce": nonce,
    })
    .to_string();
    //todo: check issued_at
    match platform {
        Platform::Apple => {
            let msg_hash = sha256_bytes(message.as_bytes()).encode_bs64();

            apple::verify_assertion_base64(
                assertion_object_base64,
                pubkey_base64,
                &msg_hash,
                app_id,
                previous_counter,
            )
            .map(|x| Some(x))
        }
        Platform::Google => {
            google::verify_attested_base64(&pubkey_base64, &message, &assertion_object_base64)?;
            Ok(None)
        }
    }
}
