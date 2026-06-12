pub mod apple;
pub mod google;

use anyhow::anyhow;

use crate::{
    codec::bs64::EncodeBs64,
    credential::common::{Platform, sha256_bytes},
};

use crate::credential::aws::is_debug_mode;

pub fn verify_assertion(
    platform: Platform,
    app_id: &str,
    assertion_object_base64: &str,
    pubkey_base64: &str,
    payload: &str,
) -> anyhow::Result<Option<u32>> {
    if is_debug_mode()? && assertion_object_base64 == "xxxxxxxx" {
        return Ok(None);
    }
    match platform {
        Platform::Apple => {
            let msg_hash = sha256_bytes(payload.as_bytes()).encode_bs64();

            apple::verify_assertion_base64(
                assertion_object_base64,
                pubkey_base64,
                &msg_hash,
                app_id,
                None,
            )
            .map(Some)
            .map_err(|e| {
                println!("{:?}", e);
                anyhow!(crate::error::Error::AssertionVerifyFailed.to_json())
            })
        }
        Platform::Google => {
            google::verify_assertion_base64(pubkey_base64, payload, assertion_object_base64)
                .map_err(|e| {
                    println!("{:?}", e);
                    anyhow!(crate::error::Error::AssertionVerifyFailed.to_json())
                })?;
            Ok(None)
        }
    }
}
