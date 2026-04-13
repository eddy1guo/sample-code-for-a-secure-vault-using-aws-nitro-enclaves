use crate::attestation::common::{
    DerElement, certificate_extension_value, find_context_specific, load_pem_certificates,
    parse_der, verify_cert_chain,
};
use anyhow::{Result, anyhow, bail};
use openssl::x509::X509;
use serde::Deserialize;
use std::collections::BTreeMap;

const ANDROID_KEY_ATTESTATION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";
const TAG_PURPOSE: u32 = 1;
const TAG_ALL_APPLICATIONS: u32 = 600;
const TAG_ORIGIN: u32 = 702;
const TAG_ROLLBACK_RESISTANCE: u32 = 703;
const TAG_ROOT_OF_TRUST: u32 = 704;
const TAG_ATTESTATION_APPLICATION_ID: u32 = 709;
const KEY_ORIGIN_GENERATED: u64 = 0;
const GOOGLE_ATTESTATION_ROOT_RSA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn
w1IdYIg2Wxg7yHcQZemFQg==
-----END CERTIFICATE-----";
const GOOGLE_ATTESTATION_ROOT_ECDSA_P384_PEM: &str = "-----BEGIN CERTIFICATE-----
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
-----END CERTIFICATE-----";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    Software,
    TrustedEnvironment,
    StrongBox,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedBootState {
    Verified,
    SelfSigned,
    Unverified,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootOfTrust {
    pub verified_boot_key: Vec<u8>,
    pub device_locked: bool,
    pub verified_boot_state: VerifiedBootState,
    pub verified_boot_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationApplicationId {
    pub package_names: Vec<String>,
    pub signature_digests: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedKeyAttestation {
    pub attestation_version: u64,
    pub attestation_security_level: SecurityLevel,
    pub keymint_version: u64,
    pub keymint_security_level: SecurityLevel,
    pub challenge: Vec<u8>,
    pub unique_id: Vec<u8>,
    pub root_of_trust: RootOfTrust,
    pub application_id: Option<AttestationApplicationId>,
    pub public_key_spki_der: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RevocationStatusList {
    pub entries: BTreeMap<String, RevocationStatusEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RevocationStatusEntry {
    pub status: RevocationState,
    #[serde(default)]
    pub expires: Option<String>,
    #[serde(default)]
    pub reason: Option<RevocationReason>,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevocationState {
    Revoked,
    Suspended,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    Superseded,
    SoftwareFlaw,
}

#[derive(Debug, Clone, Copy)]
pub struct KeyAttestationRequirements<'a> {
    pub challenge: &'a [u8],
    pub root_pems: &'a [&'a [u8]],
    pub expected_package_name: Option<&'a str>,
    pub expected_signature_digests: &'a [&'a [u8]],
    pub require_hardware_backed: bool,
    pub require_verified_boot: bool,
}

#[derive(Debug, Default)]
struct AuthorizationList {
    purposes: Vec<u64>,
    origin: Option<u64>,
    all_applications: bool,
    rollback_resistance: bool,
    root_of_trust: Option<RootOfTrust>,
    attestation_application_id: Option<AttestationApplicationId>,
}

#[derive(Debug)]
struct KeyDescription {
    attestation_version: u64,
    attestation_security_level: SecurityLevel,
    keymint_version: u64,
    keymint_security_level: SecurityLevel,
    challenge: Vec<u8>,
    unique_id: Vec<u8>,
    software_enforced: AuthorizationList,
    hardware_enforced: AuthorizationList,
}

/// Verify an Android hardware-backed key attestation certificate chain.
pub fn verify_attestation(
    certificate_chain_der: &[Vec<u8>],
    requirements: &KeyAttestationRequirements<'_>,
) -> Result<VerifiedKeyAttestation> {
    if certificate_chain_der.is_empty() {
        bail!("Android attestation certificate chain is empty");
    }
    if requirements.root_pems.is_empty() {
        bail!("Android attestation trust anchors are empty");
    }

    let leaf = X509::from_der(&certificate_chain_der[0])?;
    let intermediates = certificate_chain_der
        .iter()
        .skip(1)
        .map(|cert| X509::from_der(cert))
        .collect::<Result<Vec<_>, _>>()?;
    let roots = load_pem_certificates(requirements.root_pems)?;
    verify_cert_chain(&leaf, &intermediates, &roots)?;

    let extension = certificate_extension_value(&leaf, ANDROID_KEY_ATTESTATION_OID)?
        .ok_or_else(|| anyhow!("Android attestation extension is missing"))?;
    let key_description = parse_key_description(&extension)?;

    if key_description.challenge != requirements.challenge {
        bail!("Android attestation challenge mismatch");
    }

    let combined_origin = key_description
        .hardware_enforced
        .origin
        .or(key_description.software_enforced.origin);
    if combined_origin != Some(KEY_ORIGIN_GENERATED) {
        bail!("Android attestation key origin is not GENERATED");
    }
    if key_description.hardware_enforced.all_applications
        || key_description.software_enforced.all_applications
    {
        bail!("Android attestation must not allow all applications");
    }

    let application_id = key_description
        .hardware_enforced
        .attestation_application_id
        .clone()
        .or(key_description
            .software_enforced
            .attestation_application_id
            .clone());
    if let Some(expected_package_name) = requirements.expected_package_name {
        let application_id = application_id
            .as_ref()
            .ok_or_else(|| anyhow!("Android attestation is missing attestationApplicationId"))?;
        if !application_id
            .package_names
            .iter()
            .any(|package_name| package_name == expected_package_name)
        {
            bail!("Android attestation package name mismatch");
        }
    }
    if !requirements.expected_signature_digests.is_empty() {
        let application_id = application_id
            .as_ref()
            .ok_or_else(|| anyhow!("Android attestation is missing attestationApplicationId"))?;
        for expected_digest in requirements.expected_signature_digests {
            if !application_id
                .signature_digests
                .iter()
                .any(|actual| actual.as_slice() == *expected_digest)
            {
                bail!("Android attestation signature digest mismatch");
            }
        }
    }

    let root_of_trust = key_description
        .hardware_enforced
        .root_of_trust
        .clone()
        .or(key_description.software_enforced.root_of_trust.clone())
        .ok_or_else(|| anyhow!("Android attestation is missing RootOfTrust"))?;

    if requirements.require_hardware_backed {
        if key_description.attestation_security_level == SecurityLevel::Software
            || key_description.keymint_security_level == SecurityLevel::Software
        {
            bail!("Android attestation is not hardware backed");
        }
        if key_description.hardware_enforced.origin != Some(KEY_ORIGIN_GENERATED)
            || key_description.hardware_enforced.root_of_trust.is_none()
        {
            bail!("Android attestation is not hardware enforced");
        }
    }

    if requirements.require_verified_boot {
        if !root_of_trust.device_locked {
            bail!("Android device bootloader is not locked");
        }
        if root_of_trust.verified_boot_state != VerifiedBootState::Verified {
            bail!("Android verified boot is not in VERIFIED state");
        }
    }

    Ok(VerifiedKeyAttestation {
        attestation_version: key_description.attestation_version,
        attestation_security_level: key_description.attestation_security_level,
        keymint_version: key_description.keymint_version,
        keymint_security_level: key_description.keymint_security_level,
        challenge: key_description.challenge,
        unique_id: key_description.unique_id,
        root_of_trust,
        application_id,
        public_key_spki_der: leaf.public_key()?.public_key_to_der()?,
    })
}

pub fn google_attestation_root_pems() -> [&'static [u8]; 2] {
    [
        GOOGLE_ATTESTATION_ROOT_RSA_PEM.as_bytes(),
        GOOGLE_ATTESTATION_ROOT_ECDSA_P384_PEM.as_bytes(),
    ]
}

pub fn parse_revocation_status_list(status_json: &[u8]) -> Result<RevocationStatusList> {
    Ok(serde_json::from_slice(status_json)?)
}

pub fn check_revocation_status(
    certificate_chain_der: &[Vec<u8>],
    revocation_status: &RevocationStatusList,
) -> Result<()> {
    for cert_der in certificate_chain_der {
        let cert = X509::from_der(cert_der)?;
        let serial = cert
            .serial_number()
            .to_bn()?
            .to_hex_str()?
            .to_string()
            .to_ascii_lowercase();
        if let Some(entry) = revocation_status.entries.get(&serial) {
            bail!(
                "Android attestation certificate serial {} is {:?}{}",
                serial,
                entry.status,
                entry
                    .reason
                    .as_ref()
                    .map(|reason| format!(" ({reason:?})"))
                    .unwrap_or_default()
            );
        }
    }
    Ok(())
}

pub fn verify_google_attestation(
    certificate_chain_der: &[Vec<u8>],
    requirements: &KeyAttestationRequirements<'_>,
    revocation_status: Option<&RevocationStatusList>,
) -> Result<VerifiedKeyAttestation> {
    let roots = google_attestation_root_pems();
    let google_requirements = KeyAttestationRequirements {
        root_pems: &roots,
        ..*requirements
    };
    let verified = verify_attestation(certificate_chain_der, &google_requirements)?;

    if let Some(status) = revocation_status {
        check_revocation_status(certificate_chain_der, status)?;
    }

    Ok(verified)
}

fn parse_key_description(raw: &[u8]) -> Result<KeyDescription> {
    let (sequence, rest) = parse_der(raw)?;
    if !rest.is_empty() {
        bail!("unexpected trailing bytes in Android key description");
    }

    let fields = sequence.sequence()?;
    if fields.len() != 8 {
        bail!(
            "unexpected Android key description field count {}",
            fields.len()
        );
    }

    Ok(KeyDescription {
        attestation_version: fields[0].integer_u64()?,
        attestation_security_level: parse_security_level(fields[1].enumerated_u64()?)?,
        keymint_version: fields[2].integer_u64()?,
        keymint_security_level: parse_security_level(fields[3].enumerated_u64()?)?,
        challenge: fields[4].octet_string()?.to_vec(),
        unique_id: fields[5].octet_string()?.to_vec(),
        software_enforced: parse_authorization_list(fields[6])?,
        hardware_enforced: parse_authorization_list(fields[7])?,
    })
}

fn parse_authorization_list(element: DerElement<'_>) -> Result<AuthorizationList> {
    let children = element.sequence()?;
    let mut list = AuthorizationList::default();

    if let Some(purpose) = find_context_specific(&children, TAG_PURPOSE) {
        list.purposes = purpose
            .explicit()?
            .set()?
            .into_iter()
            .map(|value| value.integer_u64())
            .collect::<Result<Vec<_>>>()?;
    }
    if let Some(origin) = find_context_specific(&children, TAG_ORIGIN) {
        list.origin = Some(origin.explicit()?.integer_u64()?);
    }
    if let Some(all_applications) = find_context_specific(&children, TAG_ALL_APPLICATIONS) {
        all_applications.explicit()?.null()?;
        list.all_applications = true;
    }
    if let Some(rollback_resistance) = find_context_specific(&children, TAG_ROLLBACK_RESISTANCE) {
        rollback_resistance.explicit()?.null()?;
        list.rollback_resistance = true;
    }
    if let Some(root_of_trust) = find_context_specific(&children, TAG_ROOT_OF_TRUST) {
        list.root_of_trust = Some(parse_root_of_trust(root_of_trust.explicit()?)?);
    }
    if let Some(application_id) = find_context_specific(&children, TAG_ATTESTATION_APPLICATION_ID) {
        let bytes = application_id.explicit()?.octet_string()?;
        list.attestation_application_id = Some(parse_attestation_application_id(bytes)?);
    }

    Ok(list)
}

fn parse_root_of_trust(element: DerElement<'_>) -> Result<RootOfTrust> {
    let children = element.sequence()?;
    if !(3..=4).contains(&children.len()) {
        bail!("unexpected RootOfTrust field count {}", children.len());
    }

    Ok(RootOfTrust {
        verified_boot_key: children[0].octet_string()?.to_vec(),
        device_locked: children[1].boolean()?,
        verified_boot_state: parse_verified_boot_state(children[2].enumerated_u64()?)?,
        verified_boot_hash: children
            .get(3)
            .map(|field| field.octet_string().map(|value| value.to_vec()))
            .transpose()?,
    })
}

fn parse_attestation_application_id(raw: &[u8]) -> Result<AttestationApplicationId> {
    let (sequence, rest) = parse_der(raw)?;
    if !rest.is_empty() {
        bail!("unexpected trailing bytes in attestationApplicationId");
    }

    let children = sequence.sequence()?;
    if children.len() != 2 {
        bail!(
            "unexpected attestationApplicationId field count {}",
            children.len()
        );
    }

    let package_names = children[0]
        .set()?
        .into_iter()
        .map(parse_attestation_package_info)
        .collect::<Result<Vec<_>>>()?;
    let signature_digests = children[1]
        .set()?
        .into_iter()
        .map(|digest| Ok(digest.octet_string()?.to_vec()))
        .collect::<Result<Vec<_>>>()?;

    Ok(AttestationApplicationId {
        package_names,
        signature_digests,
    })
}

fn parse_attestation_package_info(element: DerElement<'_>) -> Result<String> {
    let children = element.sequence()?;
    if children.len() != 2 {
        bail!(
            "unexpected AttestationPackageInfo field count {}",
            children.len()
        );
    }
    let package_name = children[0].octet_string()?;
    let _version = children[1].integer_u64()?;
    Ok(String::from_utf8(package_name.to_vec())?)
}

fn parse_security_level(value: u64) -> Result<SecurityLevel> {
    match value {
        0 => Ok(SecurityLevel::Software),
        1 => Ok(SecurityLevel::TrustedEnvironment),
        2 => Ok(SecurityLevel::StrongBox),
        _ => bail!("unexpected Android security level {value}"),
    }
}

fn parse_verified_boot_state(value: u64) -> Result<VerifiedBootState> {
    match value {
        0 => Ok(VerifiedBootState::Verified),
        1 => Ok(VerifiedBootState::SelfSigned),
        2 => Ok(VerifiedBootState::Unverified),
        3 => Ok(VerifiedBootState::Failed),
        _ => bail!("unexpected Android verified boot state {value}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::common::sha256_bytes;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::extension::{BasicConstraints, KeyUsage};
    use openssl::x509::{X509, X509Extension, X509NameBuilder};
    use serde::Deserialize;
    use std::fs;
    use std::path::PathBuf;

    #[derive(Deserialize)]
    struct RealWorldSample {
        #[serde(rename = "attestationChallengeBase64")]
        attestation_challenge_base64: String,
        #[serde(rename = "publicKeyBase64")]
        public_key_base64: String,
        #[serde(rename = "hardwareBacked")]
        hardware_backed: bool,
        #[serde(rename = "strongBoxBacked")]
        strongbox_backed: bool,
        #[serde(rename = "attestationCertChainBase64")]
        attestation_cert_chain_base64: Vec<String>,
    }

    #[test]
    fn test_verify_attestation_accepts_hardware_backed_key() -> Result<()> {
        let root_key = generate_p256_key()?;
        let root_cert = issue_certificate("Android Root", &root_key, None, &root_key, true, &[])?;
        let leaf_key = generate_p256_key()?;

        let challenge = b"android-challenge".to_vec();
        let signature_digest = sha256_bytes(b"signing-cert");
        let extension = build_custom_extension(
            ANDROID_KEY_ATTESTATION_OID,
            &encode_key_description(
                &challenge,
                b"unique-id",
                "com.example.wallet",
                &signature_digest,
                true,
            ),
        )?;
        let leaf_cert = issue_certificate(
            "Android Leaf",
            &leaf_key,
            Some(&root_cert),
            &root_key,
            false,
            &[extension],
        )?;

        let chain = vec![leaf_cert.to_der()?];
        let root_pem = root_cert.to_pem()?;
        let requirements = KeyAttestationRequirements {
            challenge: &challenge,
            root_pems: &[root_pem.as_slice()],
            expected_package_name: Some("com.example.wallet"),
            expected_signature_digests: &[signature_digest.as_slice()],
            require_hardware_backed: true,
            require_verified_boot: true,
        };
        let verified = verify_google_attestation(&chain, &requirements, None)?;

        assert_eq!(
            verified.attestation_security_level,
            SecurityLevel::TrustedEnvironment
        );
        assert_eq!(
            verified.keymint_security_level,
            SecurityLevel::TrustedEnvironment
        );
        assert_eq!(
            verified.root_of_trust.verified_boot_state,
            VerifiedBootState::Verified
        );
        assert!(verified.root_of_trust.device_locked);
        assert_eq!(
            verified
                .application_id
                .as_ref()
                .expect("app id")
                .package_names,
            vec!["com.example.wallet".to_string()]
        );
        Ok(())
    }

    #[test]
    fn test_verify_attestation_rejects_bad_challenge() -> Result<()> {
        let root_key = generate_p256_key()?;
        let root_cert = issue_certificate("Android Root", &root_key, None, &root_key, true, &[])?;
        let leaf_key = generate_p256_key()?;
        let extension = build_custom_extension(
            ANDROID_KEY_ATTESTATION_OID,
            &encode_key_description(
                b"real-challenge",
                b"unique-id",
                "com.example.wallet",
                &sha256_bytes(b"signing-cert"),
                true,
            ),
        )?;
        let leaf_cert = issue_certificate(
            "Android Leaf",
            &leaf_key,
            Some(&root_cert),
            &root_key,
            false,
            &[extension],
        )?;

        let chain = vec![leaf_cert.to_der()?];
        let root_pem = root_cert.to_pem()?;
        let requirements = KeyAttestationRequirements {
            challenge: b"wrong-challenge",
            root_pems: &[root_pem.as_slice()],
            expected_package_name: None,
            expected_signature_digests: &[],
            require_hardware_backed: true,
            require_verified_boot: true,
        };

        let err = verify_google_attestation(&chain, &requirements, None).unwrap_err();
        assert!(err.to_string().contains("challenge mismatch"));
        Ok(())
    }

    fn verify_real_world_sample(attestation_path: &str) -> Result<()> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("attestation")
            .join(attestation_path);
        let file = fs::read_to_string(&path)
            .map_err(|err| anyhow!("failed to read {}: {err}", path.display()))?;
        let json_start = file
            .find('{')
            .ok_or_else(|| anyhow!("missing JSON object in android real-world sample"))?;
        let sample: RealWorldSample = serde_json::from_str(&file[json_start..])?;

        let challenge = STANDARD.decode(&sample.attestation_challenge_base64)?;
        let expected_public_key = STANDARD.decode(&sample.public_key_base64)?;
        let chain = sample
            .attestation_cert_chain_base64
            .iter()
            .map(|cert| STANDARD.decode(cert).map_err(anyhow::Error::from))
            .collect::<Result<Vec<Vec<u8>>>>()?;
        let requirements = KeyAttestationRequirements {
            challenge: &challenge,
            root_pems: &[],
            expected_package_name: Some("com.chainlessandroid.app"),
            expected_signature_digests: &[],
            require_hardware_backed: true,
            require_verified_boot: true,
        };

        let verified = verify_google_attestation(&chain, &requirements, None)?;

        assert_eq!(verified.challenge, challenge);
        assert_eq!(verified.public_key_spki_der, expected_public_key);
        assert!(sample.hardware_backed);
        assert!(!sample.strongbox_backed);
        assert_eq!(
            verified.attestation_security_level,
            SecurityLevel::TrustedEnvironment
        );
        assert_eq!(
            verified.keymint_security_level,
            SecurityLevel::TrustedEnvironment
        );
        assert!(verified.root_of_trust.device_locked);
        assert_eq!(
            verified.root_of_trust.verified_boot_state,
            VerifiedBootState::Verified
        );
        assert_eq!(
            verified
                .application_id
                .as_ref()
                .expect("application id")
                .package_names,
            vec!["com.chainlessandroid.app".to_string()]
        );
        Ok(())
    }

    #[test]
    fn test_all_platform_verify_attestation_accepts_real_world_sample() -> Result<()> {
        //success
        verify_real_world_sample("testdata/android_google_real_world_attestation_object.txt")?;
        verify_real_world_sample("testdata/android_xiaomi_real_world_attestation_object.txt")?;
        verify_real_world_sample("testdata/android_vivo_real_world_attestation_object.txt")?;
        //failed
        assert!(
            verify_real_world_sample("testdata/android_samsung_real_world_attestation_object.txt")
                .is_err()
        );
        assert!(
            verify_real_world_sample("testdata/android_hongmeng_real_world_attestation_object.txt")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn test_check_revocation_status_rejects_revoked_leaf_serial() -> Result<()> {
        let root_key = generate_p256_key()?;
        let root_cert = issue_certificate("Android Root", &root_key, None, &root_key, true, &[])?;
        let leaf_key = generate_p256_key()?;

        let extension = build_custom_extension(
            ANDROID_KEY_ATTESTATION_OID,
            &encode_key_description(
                b"android-challenge",
                b"unique-id",
                "com.example.wallet",
                &sha256_bytes(b"signing-cert"),
                true,
            ),
        )?;
        let leaf_cert = issue_certificate(
            "Android Leaf",
            &leaf_key,
            Some(&root_cert),
            &root_key,
            false,
            &[extension],
        )?;

        let serial = leaf_cert
            .serial_number()
            .to_bn()?
            .to_hex_str()?
            .to_string()
            .to_ascii_lowercase();
        let status = RevocationStatusList {
            entries: [(
                serial.clone(),
                RevocationStatusEntry {
                    status: RevocationState::Revoked,
                    expires: None,
                    reason: Some(RevocationReason::KeyCompromise),
                    comment: Some("test".to_string()),
                },
            )]
            .into_iter()
            .collect(),
        };

        let err = check_revocation_status(&[leaf_cert.to_der()?], &status).unwrap_err();
        assert!(err.to_string().contains(&serial));
        assert!(err.to_string().contains("Revoked"));
        Ok(())
    }

    fn generate_p256_key() -> Result<PKey<Private>> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec_key = EcKey::generate(&group)?;
        Ok(PKey::from_ec_key(ec_key)?)
    }

    fn issue_certificate(
        common_name: &str,
        key: &PKey<Private>,
        issuer_cert: Option<&X509>,
        issuer_key: &PKey<Private>,
        is_ca: bool,
        extra_extensions: &[X509Extension],
    ) -> Result<X509> {
        let mut builder = X509::builder()?;
        builder.set_version(2)?;

        let serial = BigNum::from_u32(if is_ca { 11 } else { 22 })?.to_asn1_integer()?;
        builder.set_serial_number(&serial)?;

        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", common_name)?;
        let name = name.build();

        builder.set_subject_name(&name)?;
        if let Some(issuer_cert) = issuer_cert {
            builder.set_issuer_name(issuer_cert.subject_name())?;
        } else {
            builder.set_issuer_name(&name)?;
        }
        builder.set_pubkey(key)?;

        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(30)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;

        if is_ca {
            builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
            builder.append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()?,
            )?;
        } else {
            builder.append_extension(BasicConstraints::new().critical().build()?)?;
            builder.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
        }
        for extension in extra_extensions {
            builder.append_extension2(extension)?;
        }
        builder.sign(issuer_key, MessageDigest::sha256())?;
        Ok(builder.build())
    }

    fn build_custom_extension(oid: &str, der_contents: &[u8]) -> Result<X509Extension> {
        let oid = Asn1Object::from_str(oid)?;
        let contents = Asn1OctetString::new_from_bytes(der_contents)?;
        Ok(X509Extension::new_from_der(
            oid.as_ref(),
            false,
            contents.as_ref(),
        )?)
    }

    fn encode_key_description(
        challenge: &[u8],
        unique_id: &[u8],
        package_name: &str,
        signature_digest: &[u8],
        verified_boot: bool,
    ) -> Vec<u8> {
        let software_enforced = der_sequence(vec![der_explicit(
            TAG_ATTESTATION_APPLICATION_ID,
            der_octet_string(&encode_attestation_application_id(
                package_name,
                signature_digest,
            )),
        )]);
        let hardware_enforced = der_sequence(vec![
            der_explicit(TAG_ORIGIN, der_integer(KEY_ORIGIN_GENERATED)),
            der_explicit(
                TAG_ROOT_OF_TRUST,
                encode_root_of_trust(b"boot-key", verified_boot, Some(b"boot-hash")),
            ),
        ]);

        der_sequence(vec![
            der_integer(4),
            der_enumerated(1),
            der_integer(300),
            der_enumerated(1),
            der_octet_string(challenge),
            der_octet_string(unique_id),
            software_enforced,
            hardware_enforced,
        ])
    }

    fn encode_root_of_trust(
        verified_boot_key: &[u8],
        verified_boot: bool,
        verified_boot_hash: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut fields = vec![
            der_octet_string(verified_boot_key),
            der_boolean(true),
            der_enumerated(if verified_boot { 0 } else { 2 }),
        ];
        if let Some(hash) = verified_boot_hash {
            fields.push(der_octet_string(hash));
        }
        der_sequence(fields)
    }

    fn encode_attestation_application_id(package_name: &str, signature_digest: &[u8]) -> Vec<u8> {
        der_sequence(vec![
            der_set(vec![der_sequence(vec![
                der_octet_string(package_name.as_bytes()),
                der_integer(1),
            ])]),
            der_set(vec![der_octet_string(signature_digest)]),
        ])
    }

    fn der_sequence(children: Vec<Vec<u8>>) -> Vec<u8> {
        der_tlv(universal_tag(16, true), children.concat())
    }

    fn der_set(children: Vec<Vec<u8>>) -> Vec<u8> {
        der_tlv(universal_tag(17, true), children.concat())
    }

    fn der_octet_string(value: &[u8]) -> Vec<u8> {
        der_tlv(universal_tag(4, false), value.to_vec())
    }

    fn der_integer(value: u64) -> Vec<u8> {
        der_tlv(universal_tag(2, false), encode_positive_integer(value))
    }

    fn der_enumerated(value: u64) -> Vec<u8> {
        der_tlv(universal_tag(10, false), encode_positive_integer(value))
    }

    fn der_boolean(value: bool) -> Vec<u8> {
        der_tlv(
            universal_tag(1, false),
            vec![if value { 0xff } else { 0x00 }],
        )
    }

    fn der_explicit(tag_number: u32, value: Vec<u8>) -> Vec<u8> {
        der_tlv(context_specific_tag(tag_number, true), value)
    }

    fn der_tlv(tag: Vec<u8>, value: Vec<u8>) -> Vec<u8> {
        let mut encoded = tag;
        encoded.extend_from_slice(&der_length(value.len()));
        encoded.extend_from_slice(&value);
        encoded
    }

    fn encode_positive_integer(value: u64) -> Vec<u8> {
        if value == 0 {
            return vec![0];
        }

        let mut bytes = Vec::new();
        let mut value = value;
        while value > 0 {
            bytes.push((value & 0xff) as u8);
            value >>= 8;
        }
        bytes.reverse();
        if bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0);
        }
        bytes
    }

    fn der_length(len: usize) -> Vec<u8> {
        if len < 0x80 {
            return vec![len as u8];
        }

        let mut bytes = Vec::new();
        let mut value = len;
        while value > 0 {
            bytes.push((value & 0xff) as u8);
            value >>= 8;
        }
        bytes.reverse();

        let mut encoded = vec![0x80 | bytes.len() as u8];
        encoded.extend_from_slice(&bytes);
        encoded
    }

    fn universal_tag(number: u32, constructed: bool) -> Vec<u8> {
        encode_tag(0b0000_0000, number, constructed)
    }

    fn context_specific_tag(number: u32, constructed: bool) -> Vec<u8> {
        encode_tag(0b1000_0000, number, constructed)
    }

    fn encode_tag(class_bits: u8, number: u32, constructed: bool) -> Vec<u8> {
        let constructed_bit = if constructed { 0b0010_0000 } else { 0 };
        if number < 31 {
            return vec![class_bits | constructed_bit | number as u8];
        }

        let mut tag = vec![class_bits | constructed_bit | 0x1f];
        let mut stack = Vec::new();
        let mut value = number;
        stack.push((value & 0x7f) as u8);
        value >>= 7;
        while value > 0 {
            stack.push(0x80 | (value & 0x7f) as u8);
            value >>= 7;
        }
        stack.reverse();
        tag.extend_from_slice(&stack);
        tag
    }
}
