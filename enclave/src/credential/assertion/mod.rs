pub mod apple;
pub mod google;

use crate::{
    codec::{bs64::DecodeBs64, hex::DecodeHex},
    credential::common::{Platform, TeeClient},
};

pub fn verify_attested_signature(
    client: TeeClient,
    message: &str,
    signature: &str,
) -> anyhow::Result<bool> {
    let public_key_spki_der = client.pubkey.decode_bs64()?;
    let message = message.as_bytes();
    let signature_der = signature.decode_hex()?;
    match client.platform {
        Platform::Apple => {
            apple::verify_attested_signature(&public_key_spki_der, message, &signature_der)
        }
        Platform::Google => {
            google::verify_attested_signature(&public_key_spki_der, message, &signature_der)
        }
    }
}
