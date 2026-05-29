use anyhow::{Result, bail};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Verifier as OpenSslVerifier;

use crate::codec::bs64::DecodeBs64;

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

pub fn verify_assertion_base64(
    public_key_spki_der: &str,
    message: &str,
    signature_der: &str,
) -> Result<()> {
    let public_key_spki_der = public_key_spki_der.decode_bs64()?;
    let signature_der = signature_der.decode_bs64()?;

    let public_key = PKey::public_key_from_der(&public_key_spki_der)?;
    let mut verifier = OpenSslVerifier::new(MessageDigest::sha256(), &public_key)?;
    verifier.update(&message.as_bytes())?;
    if verifier.verify(&signature_der)? {
        bail!("verify_attested_base64 failed")
    }
    Ok(())
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
        fn test_google_verify_assertion_base64() -> Result<()> {
            let public_key_spki_der = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEU9Jjm3C85DQJWo9kBqJ7O1uJWmrcQD6uz1/9oGA64LHSyMtRKBcDXJjkXEohGyuthSvaPULHndzoRmmfBgvIpA==";
            let message = r#"{"type":"ConfirmTeeDevice","message":"0102020078b745c66ff477962a0c7936db47664e72366aea22ffbe5c791a8b8de1d273e9d701bec18902886bdfb420c6e57eddfb3695000001443082014006092a864886f70d010706a08201313082012d0201003082012606092a864886f70d010701301e060960864801650304012e3011040c0fdff1d96e95dc283b814d480201108081f8c319d95637289019b1aae29bc8483de07f4c0eba0411260dde108d21e0b13b53ca74cd1d4b6d58a1891452f3cf1b73970334402aa7c9c8959ec60cb5e0e2f9cdf19a49320fcf607c5aee10fb7baabb1f13c86c789dcc13bdc00a88bd049452c42272df2a3b9465ea503c254c5d1dcc797e8a0f9033f0099a549f6416947867712200c30114d932b9aef28f1a05f1867225d4733a3dea7d8d8713e6efa36a701c9490d26366b9632057d49f79c5699459fd71b6ae43d674aa570a9e9f25fd592e9623fc2046a7aac30290ab2867db94c63915e7070592e1c464c506b1b89e3007ffa2a1313f3cc6fd69bb40b943f7c0eecbb14cfb269fe8db"}"#;
            let assertion = "MEQCIAR5vzfjU8+zpQ/jU2mZdgSYYO3OFw9g9VEAGIg9RbqsAiAi/r5y+OaQAVsLI5Zi6Z5m7wkZcihbr5Uz8iDSYp5jhA==";

            verify_assertion_base64(public_key_spki_der, message, assertion)?;
            Ok(())
        }

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
            let sample: RealWorldAssertionSample = serde_json::from_str(include_str!(
                "../testdata/android_xiaomi_real_world_assertion_object2.txt"
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
