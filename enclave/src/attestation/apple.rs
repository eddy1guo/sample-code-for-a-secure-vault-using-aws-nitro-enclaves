use crate::attestation::common::{
    certificate_extension_value, load_pem_certificates, parse_der, sha256_bytes, verify_cert_chain,
};
use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use openssl::bn::BigNumContext;
use openssl::ec::PointConversionForm;
use openssl::pkey::{PKey, Public};
use openssl::x509::X509;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use serde_cbor::Value;

const APPLE_APP_ATTEST_FORMAT: &str = "apple-appattest";
const APPLE_NONCE_EXTENSION_OID: &str = "1.2.840.113635.100.8.2";
const FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;
const APP_ATTEST_DEVELOPMENT_AAGUID: [u8; 16] = *b"appattestdevelop";
const APP_ATTEST_PRODUCTION_AAGUID: [u8; 16] = [
    b'a', b'p', b'p', b'a', b't', b't', b'e', b's', b't', 0, 0, 0, 0, 0, 0, 0,
];

#[derive(Debug, Deserialize)]
struct AppAttestationObject {
    fmt: String,
    #[serde(rename = "attStmt")]
    att_stmt: AppAttestationStatement,
    #[serde(rename = "authData")]
    auth_data: ByteBuf,
}

#[derive(Debug, Deserialize)]
struct AppAttestationStatement {
    x5c: Vec<ByteBuf>,
    #[serde(default)]
    receipt: Option<ByteBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppAttestEnvironment {
    Development,
    Production,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub key_id: Vec<u8>,
    pub counter: u32,
    pub environment: AppAttestEnvironment,
    pub receipt: Option<Vec<u8>>,
    pub public_key_spki_der: Vec<u8>,
    pub public_key_raw: Vec<u8>,
}

#[derive(Debug)]
struct ParsedAuthenticatorData {
    rp_id_hash: [u8; 32],
    flags: u8,
    counter: u32,
    aaguid: [u8; 16],
    credential_id: Vec<u8>,
    credential_public_key_raw: Vec<u8>,
}

/// Verify an iOS App Attest attestation object.
///
/// `app_id` is the App Attest relying party identifier, typically `{team_id}.{bundle_id}`.
/// `key_id` is the base64-encoded identifier returned by `DCAppAttestService::generateKey`.
/// `client_data_hash` is the challenge digest that was provided to `attestKey`.
/// `root_pem` should be the Apple App Attestation Root CA certificate.
pub fn verify_attestation(
    attestation_object: &[u8],
    app_id: &str,
    key_id: &str,
    client_data_hash: &[u8],
    root_pem: &[u8],
) -> Result<VerifiedAttestation> {
    let roots = load_pem_certificates(&[root_pem])?;
    let object = parse_attestation_object(attestation_object)?;
    if object.fmt != APPLE_APP_ATTEST_FORMAT {
        bail!("unexpected App Attest format {}", object.fmt);
    }
    if object.att_stmt.x5c.is_empty() {
        bail!("App Attest attestation statement is missing x5c certificates");
    }

    let leaf = X509::from_der(&object.att_stmt.x5c[0])?;
    let intermediates = object
        .att_stmt
        .x5c
        .iter()
        .skip(1)
        .map(|cert| X509::from_der(cert))
        .collect::<Result<Vec<_>, _>>()?;
    verify_cert_chain(&leaf, &intermediates, &roots)?;

    let auth_data = parse_authenticator_data(object.auth_data.as_slice())?;
    let expected_rp_id_hash = sha256_bytes(app_id.as_bytes());
    if auth_data.rp_id_hash.as_slice() != expected_rp_id_hash.as_slice() {
        bail!("App Attest app identity hash mismatch");
    }
    if (auth_data.flags & FLAG_ATTESTED_CREDENTIAL_DATA) == 0 {
        bail!("App Attest authData is missing attested credential data");
    }
    if auth_data.counter != 0 {
        bail!("App Attest counter must start at zero");
    }

    let environment = match auth_data.aaguid {
        APP_ATTEST_DEVELOPMENT_AAGUID => AppAttestEnvironment::Development,
        APP_ATTEST_PRODUCTION_AAGUID => AppAttestEnvironment::Production,
        other => bail!("unexpected App Attest AAGUID {}", hex::encode(other)),
    };

    let cert_public_key = leaf.public_key()?;
    let public_key_raw = public_key_raw_bytes(&cert_public_key)?;
    if auth_data.credential_public_key_raw != public_key_raw {
        bail!("credential public key does not match attestation certificate");
    }

    let decoded_key_id = decode_key_id(key_id)?;
    if decoded_key_id != auth_data.credential_id {
        bail!("App Attest key identifier does not match credential id");
    }

    let public_key_spki_der = cert_public_key.public_key_to_der()?;
    let candidate_hashes = [
        sha256_bytes(&public_key_spki_der),
        sha256_bytes(&public_key_raw),
    ];
    if !candidate_hashes
        .iter()
        .any(|candidate| *candidate == decoded_key_id)
    {
        bail!("credential id does not match the attested certificate public key");
    }

    let nonce_extension = certificate_extension_value(&leaf, APPLE_NONCE_EXTENSION_OID)?
        .ok_or_else(|| {
            anyhow!("attestation certificate is missing the App Attest nonce extension")
        })?;
    let nonce = parse_nonce_extension(&nonce_extension)?;

    let mut nonce_input = Vec::with_capacity(object.auth_data.len() + client_data_hash.len());
    nonce_input.extend_from_slice(object.auth_data.as_slice());
    nonce_input.extend_from_slice(client_data_hash);
    let expected_nonce = sha256_bytes(&nonce_input);
    if nonce != expected_nonce {
        bail!("App Attest nonce mismatch");
    }

    Ok(VerifiedAttestation {
        key_id: decoded_key_id,
        counter: auth_data.counter,
        environment,
        receipt: object.att_stmt.receipt.map(|receipt| receipt.to_vec()),
        public_key_spki_der,
        public_key_raw,
    })
}

fn parse_attestation_object(raw: &[u8]) -> Result<AppAttestationObject> {
    let value: Value = serde_cbor::from_slice(raw)?;
    let map = cbor_map(value, "App Attest attestation object")?;

    Ok(AppAttestationObject {
        fmt: text_field(&map, "fmt", "App Attest attestation object")?,
        att_stmt: parse_attestation_statement(
            map.get(&Value::Text("attStmt".to_string()))
                .ok_or_else(|| anyhow!("App Attest attestation object is missing attStmt"))?,
        )?,
        auth_data: ByteBuf::from(bytes_field_by_name(
            &map,
            "authData",
            "App Attest attestation object",
        )?),
    })
}

fn parse_attestation_statement(value: &Value) -> Result<AppAttestationStatement> {
    let map = cbor_map_ref(value, "App Attest attStmt")?;
    let x5c = match map
        .get(&Value::Text("x5c".to_string()))
        .ok_or_else(|| anyhow!("App Attest attStmt is missing x5c"))?
    {
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Bytes(bytes) => Ok(ByteBuf::from(bytes.clone())),
                _ => bail!("App Attest x5c entry is not a byte string"),
            })
            .collect::<Result<Vec<_>>>()?,
        _ => bail!("App Attest x5c is not an array"),
    };

    let receipt = match map.get(&Value::Text("receipt".to_string())) {
        Some(Value::Bytes(bytes)) => Some(ByteBuf::from(bytes.clone())),
        Some(_) => bail!("App Attest receipt is not a byte string"),
        None => None,
    };

    Ok(AppAttestationStatement { x5c, receipt })
}

fn cbor_map(value: Value, context: &str) -> Result<std::collections::BTreeMap<Value, Value>> {
    match value {
        Value::Map(map) => Ok(map),
        _ => bail!("{context} is not a CBOR map"),
    }
}

fn cbor_map_ref<'a>(
    value: &'a Value,
    context: &str,
) -> Result<&'a std::collections::BTreeMap<Value, Value>> {
    match value {
        Value::Map(map) => Ok(map),
        _ => bail!("{context} is not a CBOR map"),
    }
}

fn text_field(
    map: &std::collections::BTreeMap<Value, Value>,
    name: &str,
    context: &str,
) -> Result<String> {
    match map.get(&Value::Text(name.to_string())) {
        Some(Value::Text(value)) => Ok(value.clone()),
        Some(_) => bail!("{context} field {name} is not a text string"),
        None => bail!("{context} is missing {name}"),
    }
}

fn bytes_field_by_name(
    map: &std::collections::BTreeMap<Value, Value>,
    name: &str,
    context: &str,
) -> Result<Vec<u8>> {
    match map.get(&Value::Text(name.to_string())) {
        Some(Value::Bytes(value)) => Ok(value.clone()),
        Some(_) => bail!("{context} field {name} is not a byte string"),
        None => bail!("{context} is missing {name}"),
    }
}

fn parse_authenticator_data(raw: &[u8]) -> Result<ParsedAuthenticatorData> {
    if raw.len() < 55 {
        bail!("App Attest authData is too short");
    }

    let mut rp_id_hash = [0_u8; 32];
    rp_id_hash.copy_from_slice(&raw[..32]);
    let flags = raw[32];
    let counter = u32::from_be_bytes(raw[33..37].try_into()?);

    let mut aaguid = [0_u8; 16];
    aaguid.copy_from_slice(&raw[37..53]);

    let credential_id_len = usize::from(u16::from_be_bytes(raw[53..55].try_into()?));
    let credential_id_end = 55 + credential_id_len;
    if raw.len() < credential_id_end {
        bail!("App Attest authData has a truncated credential id");
    }

    let credential_id = raw[55..credential_id_end].to_vec();
    let credential_public_key = &raw[credential_id_end..];
    if credential_public_key.is_empty() {
        bail!("App Attest authData is missing the credential public key");
    }

    let mut deserializer = serde_cbor::de::Deserializer::from_slice(credential_public_key);
    let value = Value::deserialize(&mut deserializer)?;
    if deserializer.byte_offset() != credential_public_key.len() {
        bail!("unexpected trailing CBOR after App Attest credential public key");
    }
    let credential_public_key_raw = cose_p256_public_key(&value)?;

    Ok(ParsedAuthenticatorData {
        rp_id_hash,
        flags,
        counter,
        aaguid,
        credential_id,
        credential_public_key_raw,
    })
}

fn parse_nonce_extension(raw: &[u8]) -> Result<Vec<u8>> {
    let (sequence, rest) = parse_der(raw)?;
    if !rest.is_empty() {
        bail!("unexpected trailing bytes in App Attest nonce extension");
    }

    let children = sequence.sequence()?;
    if children.len() != 1 {
        bail!("unexpected App Attest nonce extension structure");
    }

    let tagged = children[0].expect_context_specific(1)?;
    let nonce = tagged.explicit()?.octet_string()?;
    Ok(nonce.to_vec())
}

fn cose_p256_public_key(value: &Value) -> Result<Vec<u8>> {
    let map = match value {
        Value::Map(map) => map,
        _ => bail!("credential public key is not a COSE map"),
    };

    let kty = integer_field(map, 1)?;
    let alg = integer_field(map, 3)?;
    let curve = integer_field(map, -1)?;
    let x = bytes_field(map, -2)?;
    let y = bytes_field(map, -3)?;

    if kty != 2 {
        bail!("unexpected COSE key type {kty}");
    }
    if alg != -7 {
        bail!("unexpected COSE algorithm {alg}");
    }
    if curve != 1 {
        bail!("unexpected COSE curve {curve}");
    }
    if x.len() != 32 || y.len() != 32 {
        bail!("unexpected COSE P-256 coordinate length");
    }

    let mut public_key = Vec::with_capacity(65);
    public_key.push(0x04);
    public_key.extend_from_slice(x);
    public_key.extend_from_slice(y);
    Ok(public_key)
}

fn integer_field(map: &std::collections::BTreeMap<Value, Value>, key: i128) -> Result<i128> {
    match map.get(&Value::Integer(key)) {
        Some(Value::Integer(value)) => Ok(*value),
        Some(_) => bail!("COSE field {key} is not an integer"),
        None => bail!("missing COSE field {key}"),
    }
}

fn bytes_field<'a>(
    map: &'a std::collections::BTreeMap<Value, Value>,
    key: i128,
) -> Result<&'a [u8]> {
    match map.get(&Value::Integer(key)) {
        Some(Value::Bytes(value)) => Ok(value.as_slice()),
        Some(_) => bail!("COSE field {key} is not a byte string"),
        None => bail!("missing COSE field {key}"),
    }
}

fn decode_key_id(key_id: &str) -> Result<Vec<u8>> {
    for engine in [URL_SAFE_NO_PAD, URL_SAFE, STANDARD_NO_PAD, STANDARD] {
        if let Ok(decoded) = engine.decode(key_id) {
            return Ok(decoded);
        }
    }
    bail!("App Attest key id is not valid base64")
}

fn public_key_raw_bytes(public_key: &PKey<Public>) -> Result<Vec<u8>> {
    let ec_key = public_key.ec_key()?;
    let group = ec_key.group();
    let point = ec_key.public_key();
    let mut ctx = BigNumContext::new()?;
    Ok(point.to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::extension::{BasicConstraints, KeyUsage};
    use openssl::x509::{X509, X509Extension, X509NameBuilder};
    use serde::Serialize;
    use serde_bytes::ByteBuf;

    const APPLE_APP_ATTEST_ROOT_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----";
    const REAL_SAMPLE_APP_ID: &str = "F632MRRB47.com.chainlessios.app";
    const REAL_SAMPLE_KEY_ID: &str = "iwn+VwiPoc3zAe2FBaLXmau94x2wFJE7UyGxE7nPJ3Y=";
    const REAL_SAMPLE_CLIENT_DATA_UTF8: &str = "{\"challenge\":\"YXR0ZXN0OjE3NzU1NDI4MjY1NjA6N2E1MDQ1YjI4ZGI0OWNhMTM5ODE5YjkxNDRl\",\"issuedAt\":1775542826561}";
    const REAL_SAMPLE_CLIENT_DATA_HASH_BASE64: &str =
        "NbOeAFN1xEAaRFFyW2uutyIbCq9eik4z592u73ug4Yw=";
    const REAL_SAMPLE_ATTESTATION_OBJECT: &[u8] =
        include_bytes!("testdata/ios_real_world_attestation_object.bin");
    const REAL_SAMPLE_ATTESTATION_OBJECT_HEX: &str = "a363666d746f6170706c652d6170706174746573746761747453746d74a263783563825903cb308203c73082034ea0030201020206019d6699852b300a06082a8648ce3d040302304f3123302106035504030c1a4170706c6520417070204174746573746174696f6e204341203131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e6961301e170d3236303430363036323033305a170d3236313230333138333633305a3081913149304706035504030c4038623039666535373038386661316364663330316564383530356132643739396162626465333164623031343931336235333231623131336239636632373736311a3018060355040b0c114141412043657274696669636174696f6e31133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e69613059301306072a8648ce3d020106082a8648ce3d030107034200045825f01b55600a2aaf6f38aa10a01e255b2b7c9b2d1ff692413ef514c5661621aca5aa5b1254933d84746e9be254c7645f3c0fe39b2d2969d38e285a797eb0a9a38201d1308201cd300c0603551d130101ff04023000300e0603551d0f0101ff0404030204f030140603551d25040d300b06092a864886f76364041830819106092a864886f763640805048183308180a40302010abf893003020101bf893103020100bf893203020101bf893303020101bf893421041f463633324d52524234372e636f6d2e636861696e6c657373696f732e617070a5060404736b7320bf893603020105bf893703020100bf893903020100bf893a03020100bf893b03020100aa03020100bf893c060204736b73203081cd06092a864886f7636408070481bf3081bcbf8a7806040431382e36bf885003020102bf8a79090407312e302e323136bf8a7b0704053232473836bf8a7c06040431382e36bf8a7d06040431382e36bf8a7e03020100bf8a7f03020100bf8b0003020100bf8b0103020100bf8b0203020100bf8b0303020100bf8b0403020101bf8b0503020100bf8b0a0f040d32322e372e38362e302e302c30bf8b0b0f040d32322e372e38362e302e302c30bf8b0c0f040d32322e372e38362e302e302c30bf88020a04086970686f6e656f73303306092a8648ce3d040302036700306402300a21ecbc001ed20add277abb581cb7e42515b7ccf46ecb0cbacf248ce50cfc00340101b2a0b33e7083ea11c0164af22d0230631a5f697353f63f20f5966eaa635acaf718a0b9607fccba14bf9ceaa1c9080e9347d5e836fd05108f3ff188833f42ea59024730820243308201c8a003020102021009bac5e1bc401ad9d45395bc381a0854300a06082a8648ce3d04030330523126302406035504030c1d4170706c6520417070204174746573746174696f6e20526f6f7420434131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e6961301e170d3230303331383138333935355a170d3330303331333030303030305a304f3123302106035504030c1a4170706c6520417070204174746573746174696f6e204341203131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e69613076301006072a8648ce3d020106052b8104002203620004ae5b37a0774d79b2358f40e7d1f22626f1c25fef17802deab3826a59874ff8d2ad1525789aa26604191248b63cb967069e98d363bd5e370fbfa08e329e8073a985e7746ea359a2f66f29db32af455e211658d567af9e267eb2614dc21a66ce99a366306430120603551d130101ff040830060101ff020100301f0603551d23041830168014ac91105333bdbe6841ffa70ca9e5faeae5e58aa1301d0603551d0e041604143ee35d1c0419a9c9b431f88474d6e1e15772e39b300e0603551d0f0101ff040403020106300a06082a8648ce3d0403030369003066023100bbbe888d738d0502cfbcfd666d09575035bcd6872c3f8430492629edd1f914e879991c9ae8b5aef8d3a85433f7b60d06023100ab38edd0cc81ed00a452c3ba44f993636553fecc297f2eb4df9f5ebe5a4acab6995c4b820df904386f7807bb589439b76772656365697074590f3c308006092a864886f70d010702a0803080020101310f300d06096086480165030402010500308006092a864886f70d010701a0802480048203e8318204f43027020102020101041f463633324d52524234372e636f6d2e636861696e6c657373696f732e617070308203d5020103020101048203cb308203c73082034ea0030201020206019d6699852b300a06082a8648ce3d040302304f3123302106035504030c1a4170706c6520417070204174746573746174696f6e204341203131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e6961301e170d3236303430363036323033305a170d3236313230333138333633305a3081913149304706035504030c4038623039666535373038386661316364663330316564383530356132643739396162626465333164623031343931336235333231623131336239636632373736311a3018060355040b0c114141412043657274696669636174696f6e31133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e69613059301306072a8648ce3d020106082a8648ce3d030107034200045825f01b55600a2aaf6f38aa10a01e255b2b7c9b2d1ff692413ef514c5661621aca5aa5b1254933d84746e9be254c7645f3c0fe39b2d2969d38e285a797eb0a9a38201d1308201cd300c0603551d130101ff04023000300e0603551d0f0101ff0404030204f030140603551d25040d300b06092a864886f76364041830819106092a864886f763640805048183308180a40302010abf893003020101bf893103020100bf893203020101bf893303020101bf893421041f463633324d52524234372e636f6d2e636861696e6c657373696f732e617070a5060404736b7320bf893603020105bf893703020100bf893903020100bf893a03020100bf893b03020100aa03020100bf893c060204736b73203081cd06092a864886f7636408070481bf3081bcbf8a7806040431382e36bf885003020102bf8a79090407312e302e323136bf8a7b0704053232473836bf8a7c06040431382e36bf8a7d06040431382e36bf8a7e03020100bf8a7f03020100bf8b0003020100bf8b0103020100bf8b0203020100bf8b0303020100bf8b0403020101bf8b0503020100bf8b0a0f040d32322e372e38362e302e302c30bf8b0b0f040d32322e372e38362e302e302c30bf8b0c0f040d32322e372e38362e302e302c30bf88020a04086970686f6e656f73303306092a8648ce3d040302036700306402300a21ecbc001ed20add277abb581cb7e42515b7ccf46ecb0cbacf248ce50cfc00340101b2a0b33e7083ea11c0164af22d0230631a5f697353f63f20f5966eaa635acaf71804820110a0b9607fccba14bf9ceaa1c9080e9347d5e836fd05108f3ff188833f42ea3028020104020101042035b39e005375c4401a4451725b6baeb7221b0aaf5e8a4e33e7ddaeef7ba0e18c306002010502010104583842444a6e387a6731365468672f584b4b79764e713336625675506846304979557a6263316c4f6375555a646b376c757744636d463157385553625746386a394e5471552f5865466632494e4e3479754a437a6632413d3d300e02010602010104064154544553543012020107020101040a70726f64756374696f6e301f02010c0201010417323032362d30342d30375430363a32303a33302e33395a301f0201150201010417323032362d30372d30365430363a32303a33302e33395a000000000000a080308203ae30820354a003020102021066023880001426f75d8b0e152c5f6e43300a06082a8648ce3d040302307c3130302e06035504030c274170706c65204170706c69636174696f6e20496e746567726174696f6e2043412035202d20473131263024060355040b0c1d4170706c652043657274696669636174696f6e20417574686f7269747931133011060355040a0c0a4170706c6520496e632e310b3009060355040613025553301e170d3236303132303230323130395a170d3237303231383138353833395a305a3136303406035504030c2d4170706c69636174696f6e204174746573746174696f6e2046726175642052656365697074205369676e696e6731133011060355040a0c0a4170706c6520496e632e310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d030107034200043b18aecec519ad8a5351b44044b4a3039957b4cdbd5b851fe01a6fede28defb0fab0c36a02a41f446e006d580e568a67808907f3488091438b20ceaa4c9ddc56a38201d8308201d4300c0603551d130101ff04023000301f0603551d23041830168014d917fe4b6790384b92f4dbced55780140b8f3dc9304306082b0601050507010104373035303306082b060105050730018627687474703a2f2f6f6373702e6170706c652e636f6d2f6f63737030332d616169636135673130313082011c0603551d20048201133082010f3082010b06092a864886f7636405013081fd3081c306082b060105050702023081b60c81b352656c69616e6365206f6e207468697320636572746966696361746520627920616e7920706172747920617373756d657320616363657074616e6365206f6620746865207468656e206170706c696361626c65207374616e64617264207465726d7320616e6420636f6e646974696f6e73206f66207573652c20636572746966696361746520706f6c69637920616e642063657274696669636174696f6e2070726163746963652073746174656d656e74732e303506082b060105050702011629687474703a2f2f7777772e6170706c652e636f6d2f6365727469666963617465617574686f72697479301d0603551d0e041604143455897074600e22d2ba67cfa55b69c223f1ca28300e0603551d0f0101ff040403020780300f06092a864886f763640c0f04020500300a06082a8648ce3d040302034800304502201c6797b98245d1d6dc7204b79b023caff87bf2eff8937dd720c45e8ae465c2eb022100fcc85984cec9a12cc286a9d49276fdf0d2f625dc75fc7cf88745697be61eaab4308202f93082027fa003020102021056fb83d42bff8dc3379923b55aae6ebd300a06082a8648ce3d0403033067311b301906035504030c124170706c6520526f6f74204341202d20473331263024060355040b0c1d4170706c652043657274696669636174696f6e20417574686f7269747931133011060355040a0c0a4170706c6520496e632e310b3009060355040613025553301e170d3139303332323137353333335a170d3334303332323030303030305a307c3130302e06035504030c274170706c65204170706c69636174696f6e20496e746567726174696f6e2043412035202d20473131263024060355040b0c1d4170706c652043657274696669636174696f6e20417574686f7269747931133011060355040a0c0a4170706c6520496e632e310b30090603550406130255533059301306072a86488648ce3d020106082a8648ce3d0301070342000124b398ef5f61ac6aca028ec7386bfec12520246b3d8c77e9b2ca0d5bd112f8487955f744a3636ea09f256f927eaf8cf2abb341067c4bd0c97ebd2facf2e0dfaea8e07dcc207d0c03c180d54744c0407fc1014c00c0407fcc07c180d54748c1060c05a0052eec37a8560ce226a922a677afaf7aebf6b2c92acc1181820ac180414141c040410e8c0e0c0d81820ac180414141cc00618a9a1d1d1c0e8bcbdbd8dcdc0b985c1c1b194b98dbdb4bdbd8dcdc0c0ccb585c1c1b195c9bdbdd18d859cccc0dc180d54747c10c0c0b8c0b280aa80a21899a1d1d1c0e8bcbd8dc9b0b985c1c1b194b98dbdb4bd85c1c1b195c9bdbdd18d859cccb98dc9b0c074180d54743810581053645ff92d9e40e12e4bd36f3b555e00502e3cf724c038180d54743c0407fc10100c080418c0401828aa19221bdd8d9018080c10081400c0281820aa192338f4100c0cc19cc46cc064180d54100c304905c1c1b1948149bdbdd0810d0480b4811cccc498c090180d54102c307505c1c1b194810d95c9d1a599a58d85d1a5bdb88105d5d1a1bdc9a5d1e4c44cc044180d541028302905c1c1b1948125b98cb8c42cc024180d5410184c09554cc0785c34c4d0c0d0ccc0c4e0c4e4c0d9685c34cce4c0d0ccc0c4e0c4e4c0d968c19cc46cc064180d54100c304905c1c1b1948149bdbdd0810d0480b4811cccc498c090180d54102c307505c1c1b194810d95c9d1a599a58d85d1a5bdb88105d5d1a1bdc9a5d1e4c44cc044180d541028302905c1c1b1948125b98cb8c42cc024180d5410184c09554c1d8c040181caa192338f408041814ae041000880d88001263a4bcf501ca93b64c89ca044c73744257c7168d39c770505b643b969814a9dd91ed7d38e34eec7112d5ffd47ed8c9897727a6116d3cc13c456803f561603297d43cb1341d1c4dd76a5e5e5dbcc573b4ae75ec80ef62e553657a6690e94428c68d08c100c074180d54743810581052eec37a8560ce226a922a677afaf7aebf6b2c92acc03c180d54744c0407fc1014c00c0407fcc038180d54743c0407fc10100c080418c0281820aa192338f4100c0c0da000c19408c4020fa7071059786974d06367b7bfd1b03801192ee37ec91847143ff799ea328699af3b080f5273d64f19d2e1ab7ea88c5408c1b59a28432b5037513f36350cfad2298e94cdbb8db7685edd907f214c9be62189d0e42c5d6f2d46a033a0600f9e8ac8a00000c607f4c207e8080404c20640c1f0c4c0c0b8180d54100c309d05c1c1b1948105c1c1b1a58d85d1a5bdb88125b9d1959dc985d1a5bdb8810d0480d480b4811cc4c498c090180d54102c307505c1c1b194810d95c9d1a599a58d85d1a5bdb88105d5d1a1bdc9a5d1e4c44cc044180d541028302905c1c1b1948125b98cb8c42cc024180d5410184c09554c08419808e20000509bdd762c3854b17db90cc034182582192005940c1008041400c0281820aa192338f4100c08111cc114088402d18ddcedea66055fdce2042251757c47097abe941c32f8316dd36b19bc8c85c408819e10b722136285d2a70bc86e9a25ca4a61975a509c88a7e385f8fa8a48f50038000000000001a185d5d1a11185d185629312cd2d8b1e936dc7b7a96ad79c57f77b6ecfc2662fc5a0ddef9b68b9db2b1945000000000185c1c185d1d195cdd00000000000000000822c27f95c223e8737cc07b614168b5e66aef78c76c05244ed4c86c44ee73c9dda9404080c9880048560816097c06d558028aabdbce2a8428078956cadf26cb47fda4904fbd45315985884896082b296a96c49524cf611d1ba6f89531d917cf03f8e6cb4a5a74e38a169e5fac2a";

    #[derive(Serialize)]
    struct EncodedAttestationObject {
        fmt: String,
        #[serde(rename = "attStmt")]
        att_stmt: EncodedAttestationStatement,
        #[serde(rename = "authData")]
        auth_data: ByteBuf,
    }

    #[derive(Serialize)]
    struct EncodedAttestationStatement {
        x5c: Vec<ByteBuf>,
        #[serde(skip_serializing_if = "Option::is_none")]
        receipt: Option<ByteBuf>,
    }

    #[derive(Deserialize)]
    struct RealWorldSample {
        #[serde(rename = "keyId")]
        key_id: String,
        #[serde(rename = "clientDataUtf8")]
        client_data_utf8: String,
        #[serde(rename = "clientDataHashBase64")]
        client_data_hash_base64: String,
        #[serde(rename = "attestationObjectBase64")]
        attestation_object_base64: String,
    }

    #[test]
    fn test_verify_attestation_accepts_valid_development_attestation() -> Result<()> {
        let root_key = generate_p256_key()?;
        let root_cert = issue_certificate(
            "Apple App Attest Root",
            &root_key,
            None,
            &root_key,
            true,
            &[],
        )?;

        let intermediate_key = generate_p256_key()?;
        let intermediate_cert = issue_certificate(
            "Apple App Attest Intermediate",
            &intermediate_key,
            Some(&root_cert),
            &root_key,
            true,
            &[],
        )?;

        let leaf_key = generate_p256_key()?;
        let app_id = "ABCD1234.com.example.wallet";
        let client_data_hash = sha256_bytes(b"attestation-challenge");
        let leaf_public_key = PKey::public_key_from_der(&leaf_key.public_key_to_der()?)?;
        let leaf_public_key_raw = public_key_raw_bytes(&leaf_public_key)?;
        let key_id_bytes = sha256_bytes(&leaf_public_key_raw);
        let credential_public_key = cose_public_key_from_ec_key(&leaf_key)?;
        let auth_data = build_auth_data(
            app_id,
            &key_id_bytes,
            &credential_public_key,
            AppAttestEnvironment::Development,
        );
        let mut nonce_input = auth_data.clone();
        nonce_input.extend_from_slice(&client_data_hash);
        let nonce = sha256_bytes(&nonce_input);

        let nonce_extension =
            build_custom_extension(APPLE_NONCE_EXTENSION_OID, &encode_nonce_extension(&nonce))?;
        let leaf_cert = issue_certificate(
            "Leaf",
            &leaf_key,
            Some(&intermediate_cert),
            &intermediate_key,
            false,
            &[nonce_extension],
        )?;

        let receipt = b"synthetic-receipt".to_vec();
        let attestation_object = encode_attestation_object(
            &auth_data,
            &[leaf_cert.to_der()?, intermediate_cert.to_der()?],
            Some(receipt.clone()),
        )?;
        let verified = verify_attestation(
            &attestation_object,
            app_id,
            &URL_SAFE_NO_PAD.encode(&key_id_bytes),
            &client_data_hash,
            &root_cert.to_pem()?,
        )?;

        assert_eq!(verified.environment, AppAttestEnvironment::Development);
        assert_eq!(verified.counter, 0);
        assert_eq!(verified.key_id, key_id_bytes);
        assert_eq!(verified.receipt, Some(receipt));
        assert_eq!(verified.public_key_raw, leaf_public_key_raw);
        Ok(())
    }

    #[test]
    fn test_verify_attestation_rejects_wrong_app_id() -> Result<()> {
        let root_key = generate_p256_key()?;
        let root_cert = issue_certificate(
            "Apple App Attest Root",
            &root_key,
            None,
            &root_key,
            true,
            &[],
        )?;
        let leaf_key = generate_p256_key()?;
        let leaf_public_key = PKey::public_key_from_der(&leaf_key.public_key_to_der()?)?;
        let key_id_bytes = sha256_bytes(&public_key_raw_bytes(&leaf_public_key)?);
        let app_id = "ABCD1234.com.example.wallet";
        let client_data_hash = sha256_bytes(b"challenge");
        let credential_public_key = cose_public_key_from_ec_key(&leaf_key)?;
        let auth_data = build_auth_data(
            app_id,
            &key_id_bytes,
            &credential_public_key,
            AppAttestEnvironment::Development,
        );
        let mut nonce_input = auth_data.clone();
        nonce_input.extend_from_slice(&client_data_hash);
        let nonce = sha256_bytes(&nonce_input);
        let nonce_extension =
            build_custom_extension(APPLE_NONCE_EXTENSION_OID, &encode_nonce_extension(&nonce))?;
        let leaf_cert = issue_certificate(
            "Leaf",
            &leaf_key,
            Some(&root_cert),
            &root_key,
            false,
            &[nonce_extension],
        )?;
        let attestation_object =
            encode_attestation_object(&auth_data, &[leaf_cert.to_der()?], None)?;

        let err = verify_attestation(
            &attestation_object,
            "ABCD1234.com.example.other",
            &URL_SAFE_NO_PAD.encode(&key_id_bytes),
            &client_data_hash,
            &root_cert.to_pem()?,
        )
        .unwrap_err();

        assert!(err.to_string().contains("app identity hash mismatch"));
        Ok(())
    }

    fn test_verify_attestation_accepts_real_world_sample() -> Result<()> {
        let sample: RealWorldSample = serde_json::from_str(include_str!(
            "./testdata/ios_real_world_attestation_object.txt"
        ))?;
        let expected_client_data_hash = sha256_bytes(sample.client_data_utf8.as_bytes());
        let provided_client_data_hash = STANDARD.decode(&sample.client_data_hash_base64)?;
        assert_eq!(provided_client_data_hash, expected_client_data_hash);
        let attestation_object = STANDARD.decode(&sample.attestation_object_base64)?;

        let verified = verify_attestation(
            &attestation_object,
            REAL_SAMPLE_APP_ID,
            &sample.key_id,
            &provided_client_data_hash,
            APPLE_APP_ATTEST_ROOT_CA_PEM.as_bytes(),
        )?;

        assert_eq!(verified.environment, AppAttestEnvironment::Production);
        assert_eq!(verified.counter, 0);
        assert!(verified.receipt.is_some());
        assert_eq!(verified.key_id, STANDARD.decode(&sample.key_id)?);
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

        let serial = BigNum::from_u32(if is_ca { 1 } else { 2 })?.to_asn1_integer()?;
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

    fn encode_attestation_object(
        auth_data: &[u8],
        chain: &[Vec<u8>],
        receipt: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let object = EncodedAttestationObject {
            fmt: APPLE_APP_ATTEST_FORMAT.to_string(),
            att_stmt: EncodedAttestationStatement {
                x5c: chain.iter().cloned().map(ByteBuf::from).collect(),
                receipt: receipt.map(ByteBuf::from),
            },
            auth_data: ByteBuf::from(auth_data.to_vec()),
        };
        Ok(serde_cbor::to_vec(&object)?)
    }

    fn build_auth_data(
        app_id: &str,
        credential_id: &[u8],
        credential_public_key: &[u8],
        environment: AppAttestEnvironment,
    ) -> Vec<u8> {
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&sha256_bytes(app_id.as_bytes()));
        auth_data.push(FLAG_ATTESTED_CREDENTIAL_DATA);
        auth_data.extend_from_slice(&0_u32.to_be_bytes());
        auth_data.extend_from_slice(match environment {
            AppAttestEnvironment::Development => &APP_ATTEST_DEVELOPMENT_AAGUID,
            AppAttestEnvironment::Production => &APP_ATTEST_PRODUCTION_AAGUID,
        });
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend_from_slice(credential_public_key);
        auth_data
    }

    fn cose_public_key_from_ec_key(key: &PKey<Private>) -> Result<Vec<u8>> {
        let raw = public_key_raw_bytes(&PKey::public_key_from_der(&key.public_key_to_der()?)?)?;
        let x = raw
            .get(1..33)
            .ok_or_else(|| anyhow!("missing x coordinate"))?
            .to_vec();
        let y = raw
            .get(33..65)
            .ok_or_else(|| anyhow!("missing y coordinate"))?
            .to_vec();
        let map = Value::Map(
            [
                (Value::Integer(1), Value::Integer(2)),
                (Value::Integer(3), Value::Integer(-7)),
                (Value::Integer(-1), Value::Integer(1)),
                (Value::Integer(-2), Value::Bytes(x)),
                (Value::Integer(-3), Value::Bytes(y)),
            ]
            .into_iter()
            .collect(),
        );
        Ok(serde_cbor::to_vec(&map)?)
    }

    fn encode_nonce_extension(nonce: &[u8]) -> Vec<u8> {
        der_sequence(vec![der_explicit(1, der_octet_string(nonce))])
    }

    fn der_sequence(children: Vec<Vec<u8>>) -> Vec<u8> {
        der_constructed(0x30, children.concat())
    }

    fn der_octet_string(value: &[u8]) -> Vec<u8> {
        der_constructed(0x04, value.to_vec())
    }

    fn der_explicit(tag_number: u8, value: Vec<u8>) -> Vec<u8> {
        der_constructed(0xa0 | tag_number, value)
    }

    fn der_constructed(tag: u8, value: Vec<u8>) -> Vec<u8> {
        let mut encoded = vec![tag];
        encoded.extend_from_slice(&der_length(value.len()));
        encoded.extend_from_slice(&value);
        encoded
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
}
