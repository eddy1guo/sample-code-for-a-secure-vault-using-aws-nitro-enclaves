use anyhow::Result;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Verifier as OpenSslVerifier;

/// Verify an ECDSA-SHA256 signature with the public key proved by Android attestation.
pub fn verify_attested_signature(
    public_key_spki_der: &[u8],
    message: &[u8],
    signature_der: &[u8],
) -> Result<bool> {
    let public_key = PKey::public_key_from_der(public_key_spki_der)?;
    let mut verifier = OpenSslVerifier::new(MessageDigest::sha256(), &public_key)?;
    verifier.update(message)?;
    Ok(verifier.verify(signature_der)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::sign::Signer;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct RealWorldAssertionSample {
        #[serde(rename = "clientDataUtf8")]
        client_data_utf8: String,
        #[serde(rename = "publicKeyBase64")]
        public_key_base64: String,
        #[serde(rename = "payloadBase64")]
        payload_base64: String,
        #[serde(rename = "signatureBase64")]
        signature_base64: String,
    }

    mod verify_attested_signature_cases {
        use super::*;

        #[test]
        fn accepts_valid_signature() -> Result<()> {
            let key = generate_p256_key()?;
            let public_key_spki_der = key.public_key_to_der()?;
            let message = b"google-attested-signature";

            let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
            signer.update(message)?;
            let signature = signer.sign_to_vec()?;

            assert!(verify_attested_signature(
                &public_key_spki_der,
                message,
                &signature
            )?);
            Ok(())
        }

        #[test]
        fn accepts_real_world_android_assertion_sample() -> Result<()> {
            let sample: RealWorldAssertionSample = serde_json::from_str(include_str!(
                "../testdata/android_xiaomi_real_world_assertion_object.txt"
            ))?;
            let payload = STANDARD.decode(&sample.payload_base64)?;
            assert_eq!(payload, sample.client_data_utf8.as_bytes());

            let public_key_spki_der = STANDARD.decode(&sample.public_key_base64)?;
            let signature_der = STANDARD.decode(&sample.signature_base64)?;

            assert!(verify_attested_signature(
                &public_key_spki_der,
                sample.client_data_utf8.as_bytes(),
                &signature_der
            )?);
            Ok(())
        }
    }

    fn generate_p256_key() -> Result<PKey<Private>> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec_key = EcKey::generate(&group)?;
        Ok(PKey::from_ec_key(ec_key)?)
    }
}
