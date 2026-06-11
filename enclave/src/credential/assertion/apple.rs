use crate::credential::common::sha256_bytes;
use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Verifier as OpenSslVerifier;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use serde_cbor::Value;

const FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;

#[derive(Debug, Deserialize)]
struct AppAssertionObject {
    /// Assertion signature in ASN.1 DER / X9.62 format.
    signature: ByteBuf,
    /// Reduced WebAuthn authenticator data carrying rpIdHash, flags and counter.
    #[serde(rename = "authenticatorData")]
    authenticator_data: ByteBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAssertion {
    /// Assertion counter, which must strictly increase.
    pub counter: u32,
}

#[derive(Debug)]
struct ParsedAssertionAuthenticatorData {
    /// `SHA256(app_id)`.
    rp_id_hash: [u8; 32],
    /// WebAuthn flags byte.
    flags: u8,
    /// Assertion counter.
    counter: u32,
}

/// Verify an iOS App Attest assertion object.
///
/// `public_key_spki_der` should come from a previously verified attestation object.
/// `app_id` should be `{team_id}.{bundle_id}`.
/// `client_data_hash` should be the SHA-256 hash supplied to `generateAssertion`.
/// `previous_counter` should be the last accepted assertion counter for this key, if any.
pub fn verify_assertion(
    assertion_object: &[u8],
    public_key_spki_der: &[u8],
    app_id: &str,
    client_data_hash: &[u8],
    previous_counter: Option<u32>,
) -> Result<VerifiedAssertion> {
    let assertion = parse_assertion_object(assertion_object)?;
    let auth_data = parse_assertion_authenticator_data(assertion.authenticator_data.as_slice())?;
    let expected_rp_id_hash = sha256_bytes(app_id.as_bytes());
    if auth_data.rp_id_hash.as_slice() != expected_rp_id_hash.as_slice() {
        bail!("App Attest assertion app identity hash mismatch");
    }
    if (auth_data.flags & FLAG_ATTESTED_CREDENTIAL_DATA) == 0 {
        bail!("App Attest assertion authData is missing attested credential data");
    }

    let public_key = PKey::public_key_from_der(public_key_spki_der)?;
    let mut nonce_input =
        Vec::with_capacity(assertion.authenticator_data.len() + client_data_hash.len());
    nonce_input.extend_from_slice(assertion.authenticator_data.as_slice());
    nonce_input.extend_from_slice(client_data_hash);
    let nonce = sha256_bytes(&nonce_input);

    let signature = EcdsaSig::from_der(assertion.signature.as_slice())?;
    let ec_public_key = public_key.ec_key()?;
    let direct_digest_valid = signature.verify(&nonce, &ec_public_key)?;
    let frontend_compatible_valid = if direct_digest_valid {
        false
    } else {
        // Some frontend/WebCrypto flows first compute SHA256(authenticatorData || clientDataHash)
        // and then pass that digest into an ES256 verifier, which hashes once more internally.
        verify_attested_signature(public_key_spki_der, &nonce, assertion.signature.as_slice())?
    };
    if !direct_digest_valid && !frontend_compatible_valid {
        bail!("App Attest assertion signature verification failed");
    }

    Ok(VerifiedAssertion {
        counter: auth_data.counter,
    })
}

pub fn verify_assertion_base64(
    assertion_object_base64: &str,
    public_key_spki_der_base64: &str,
    client_data_hash_base64: &str,
    app_id: &str,
    previous_counter: Option<u32>,
) -> Result<u32> {
    let assertion_object = STANDARD
        .decode(assertion_object_base64)
        .map_err(|err| anyhow!("failed to base64 decode App Attest assertion object: {err}"))?;
    let public_key_spki_der = STANDARD
        .decode(public_key_spki_der_base64)
        .map_err(|err| anyhow!("failed to base64 decode App Attest assertion public key: {err}"))?;
    let client_data_hash = STANDARD.decode(client_data_hash_base64).map_err(|err| {
        anyhow!("failed to base64 decode App Attest assertion clientDataHash: {err}")
    })?;

    let res = verify_assertion(
        &assertion_object,
        &public_key_spki_der,
        &app_id,
        &client_data_hash,
        previous_counter,
    )?;
    Ok(res.counter)
}

/// Verify an ECDSA-SHA256 signature using the public key proved by attestation.
///
/// `signature_der` should be ASN.1 DER / X9.62 encoded.
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

fn parse_assertion_object(raw: &[u8]) -> Result<AppAssertionObject> {
    let value: Value = serde_cbor::from_slice(raw)?;
    let map = cbor_map(value, "App Attest assertion object")?;

    Ok(AppAssertionObject {
        signature: ByteBuf::from(bytes_field_by_name(
            &map,
            "signature",
            "App Attest assertion object",
        )?),
        authenticator_data: ByteBuf::from(bytes_field_by_name(
            &map,
            "authenticatorData",
            "App Attest assertion object",
        )?),
    })
}

fn cbor_map(value: Value, context: &str) -> Result<std::collections::BTreeMap<Value, Value>> {
    match value {
        Value::Map(map) => Ok(map.into_iter().collect()),
        _ => bail!("{context} is not a CBOR map"),
    }
}

fn bytes_field_by_name(
    map: &std::collections::BTreeMap<Value, Value>,
    name: &str,
    context: &str,
) -> Result<Vec<u8>> {
    match map.get(&Value::Text(name.to_string())) {
        Some(Value::Bytes(bytes)) => Ok(bytes.clone()),
        Some(_) => bail!("{context}.{name} is not a byte string"),
        None => bail!("{context} is missing {name}"),
    }
}

fn parse_assertion_authenticator_data(raw: &[u8]) -> Result<ParsedAssertionAuthenticatorData> {
    if raw.len() != 37 {
        bail!("App Attest assertion authenticatorData must be exactly 37 bytes");
    }

    let mut rp_id_hash = [0_u8; 32];
    rp_id_hash.copy_from_slice(&raw[..32]);
    let flags = raw[32];
    let counter = u32::from_be_bytes(raw[33..37].try_into()?);

    Ok(ParsedAssertionAuthenticatorData {
        rp_id_hash,
        flags,
        counter,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::attestation::apple::RealWorldSample;
    use base64::engine::general_purpose::STANDARD;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::sign::Signer;
    use serde::Deserialize;
    use serde::Serialize;
    use serde_bytes::ByteBuf;
    const REAL_SAMPLE_APP_ID: &str = "F632MRRB47.com.chainlessios.app";

    #[derive(Serialize)]
    struct EncodedAssertionObject {
        signature: ByteBuf,
        #[serde(rename = "authenticatorData")]
        authenticator_data: ByteBuf,
    }

    #[derive(Deserialize)]
    struct RealWorldAssertionSample {
        #[serde(rename = "clientDataUtf8")]
        client_data_utf8: String,
        #[serde(rename = "clientDataHashBase64")]
        client_data_hash_base64: String,
        #[serde(rename = "assertionObjectBase64")]
        assertion_object_base64: String,
    }

    mod verify_attested_signature_cases {
        use crate::codec::bs64::EncodeBs64;

        use super::*;

        #[test]
        fn accepts_valid_signature() -> Result<()> {
            let key = generate_p256_key()?;
            let public_key_spki_der = key.public_key_to_der()?;
            let message = b"apple-attested-signature";

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
    }

    mod verify_assertion_cases {
        use crate::codec::bs64::{DecodeBs64, EncodeBs64};

        use super::*;

        #[test]
        fn accepts_synthetic_sample() -> Result<()> {
            let key = generate_p256_key()?;
            let public_key_spki_der = key.public_key_to_der()?;
            let client_data_hash = sha256_bytes(b"synthetic-assertion-client-data");
            let auth_data = build_assertion_auth_data(REAL_SAMPLE_APP_ID, 1);
            let mut nonce_input = auth_data.clone();
            nonce_input.extend_from_slice(&client_data_hash);
            let nonce = sha256_bytes(&nonce_input);
            let ec_private_key = key.ec_key()?;
            let signature = EcdsaSig::sign(&nonce, &ec_private_key)?.to_der()?;
            let assertion_object = encode_assertion_object(&auth_data, &signature)?;

            let verified = verify_assertion(
                &assertion_object,
                &public_key_spki_der,
                REAL_SAMPLE_APP_ID,
                &client_data_hash,
                Some(0),
            )?;

            assert_eq!(verified.counter, 1);
            Ok(())
        }

        #[test]
        fn accepts_real_world_sample_base64() -> Result<()> {
            let attestation: RealWorldSample = serde_json::from_str(include_str!(
                "../testdata/ios_real_world_attestation_object.txt"
            ))?;
            let assertion: RealWorldAssertionSample = serde_json::from_str(include_str!(
                "../testdata/ios_real_world_assertion_object.txt"
            ))?;

            attestation.verify()?;

            let assertion_client_data_hash =
                sha256_bytes(assertion.client_data_utf8.as_bytes()).encode_bs64();
            let verified_assertion = verify_assertion_base64(
                &assertion.assertion_object_base64,
                &attestation.pubkey()?,
                REAL_SAMPLE_APP_ID,
                &assertion_client_data_hash,
                Some(0),
            )?;
            assert_eq!(verified_assertion, 1);
            Ok(())
        }

        #[test]
        fn accepts_real_world_sample_with_frontend_compatibility() -> Result<()> {
            let attestation: RealWorldSample = serde_json::from_str(include_str!(
                "../testdata/ios_real_world_attestation_object.txt"
            ))?;
            let assertion: RealWorldAssertionSample = serde_json::from_str(include_str!(
                "../testdata/ios_real_world_assertion_object.txt"
            ))?;
            let attestation: RealWorldSample = serde_json::from_str(include_str!(
                "../testdata/ios_real_world_attestation_object2.txt"
            ))?;
            let assertion: RealWorldAssertionSample = serde_json::from_str(include_str!(
                "../testdata/ios_real_world_assertion_object2.txt"
            ))?;

            attestation.verify()?;

            let assertion_client_data_hash = STANDARD.decode(&assertion.client_data_hash_base64)?;
            assert_eq!(
                assertion_client_data_hash,
                sha256_bytes(assertion.client_data_utf8.as_bytes())
            );

            let assertion_object = STANDARD.decode(&assertion.assertion_object_base64)?;
            let parsed_assertion = parse_assertion_object(&assertion_object)?;
            let auth_data =
                parse_assertion_authenticator_data(parsed_assertion.authenticator_data.as_slice())?;
            let expected_rp_id_hash = sha256_bytes(REAL_SAMPLE_APP_ID.as_bytes());
            assert_eq!(
                auth_data.rp_id_hash.as_slice(),
                expected_rp_id_hash.as_slice()
            );
            assert_eq!(auth_data.flags, FLAG_ATTESTED_CREDENTIAL_DATA);
            assert_eq!(auth_data.counter, 1);

            let public_key_spki_der = STANDARD.decode(&attestation.pubkey()?)?;
            let mut nonce_input = Vec::with_capacity(
                parsed_assertion.authenticator_data.len() + assertion_client_data_hash.len(),
            );
            nonce_input.extend_from_slice(parsed_assertion.authenticator_data.as_slice());
            nonce_input.extend_from_slice(&assertion_client_data_hash);
            let nonce = sha256_bytes(&nonce_input);

            let public_key = PKey::public_key_from_der(&public_key_spki_der)?;
            let ec_public_key = public_key.ec_key()?;
            let signature = EcdsaSig::from_der(parsed_assertion.signature.as_slice())?;
            assert!(!signature.verify(&nonce, &ec_public_key)?);
            //        verify_attested_signature(public_key_spki_der, &nonce, assertion.signature.as_slice())?
            assert!(verify_attested_signature(
                &public_key_spki_der,
                &nonce,
                parsed_assertion.signature.as_slice(),
            )?);

            let verified_assertion = verify_assertion(
                &assertion_object,
                &public_key_spki_der,
                REAL_SAMPLE_APP_ID,
                &assertion_client_data_hash,
                Some(0),
            )?;

            assert_eq!(verified_assertion.counter, 1);
            Ok(())
        }
    }

    fn generate_p256_key() -> Result<PKey<Private>> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec_key = EcKey::generate(&group)?;
        Ok(PKey::from_ec_key(ec_key)?)
    }

    fn encode_assertion_object(auth_data: &[u8], signature_der: &[u8]) -> Result<Vec<u8>> {
        let object = EncodedAssertionObject {
            signature: ByteBuf::from(signature_der.to_vec()),
            authenticator_data: ByteBuf::from(auth_data.to_vec()),
        };
        Ok(serde_cbor::to_vec(&object)?)
    }

    fn build_assertion_auth_data(app_id: &str, counter: u32) -> Vec<u8> {
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&sha256_bytes(app_id.as_bytes()));
        auth_data.push(FLAG_ATTESTED_CREDENTIAL_DATA);
        auth_data.extend_from_slice(&counter.to_be_bytes());
        auth_data
    }
}
