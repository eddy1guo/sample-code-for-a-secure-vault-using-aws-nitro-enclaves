pub mod apple;
pub mod google;

use crate::credential::common::Platform;
use anyhow::Result;

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
