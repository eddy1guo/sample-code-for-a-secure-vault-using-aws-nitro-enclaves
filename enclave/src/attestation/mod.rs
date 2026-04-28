use crate::{
    attestation::common::{Platform, TeeClient},
    codec::{bs64::DecodeBs64, hex::DecodeHex},
};
use anyhow::Result;

pub mod common;

pub mod apple;
pub mod aws;
pub mod google;

pub enum Attestation {
    Google(google::RealWorldSample),
    Apple(apple::RealWorldSample),
}

impl TryFrom<(String, Platform)> for Attestation {
    type Error = anyhow::Error;

    fn try_from((attestation, platform): (String, Platform)) -> Result<Self, Self::Error> {
        let attestation = match platform {
            Platform::Apple => {
                let attestation = serde_json::from_str(&attestation)?;
                Attestation::Apple(attestation)
            }
            Platform::Google => {
                let attestation = serde_json::from_str(&attestation)?;
                Attestation::Google(attestation)
            }
        };
        Ok(attestation)
    }
}

impl Attestation {
    pub fn verify(&self) -> Result<()> {
        match self {
            Attestation::Google(sample) => sample.verify(),
            Attestation::Apple(sample) => sample.verify(),
        }
    }

    pub fn pubkey(&self) -> Result<String, anyhow::Error> {
        let key = match self {
            Attestation::Google(sample) => sample.public_key_base64.to_owned(),
            Attestation::Apple(sample) => sample.pubkey()?,
        };
        Ok(key)
    }
}

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
