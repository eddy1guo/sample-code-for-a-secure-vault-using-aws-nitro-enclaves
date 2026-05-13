use crate::codec::bs64::DecodeBs64;
use crate::credential::common::{
    certificate_extension_value, load_pem_certificates, parse_der, sha256_bytes, verify_cert_chain,
};
use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use openssl::bn::BigNumContext;
use openssl::ec::PointConversionForm;
use openssl::pkey::{PKey, Public};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_cbor::Value;

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
//todo: 这里动态配置
const REAL_SAMPLE_APP_ID: &str = "F632MRRB47.com.chainlessios.app";

const APPLE_APP_ATTEST_FORMAT: &str = "apple-appattest";
const APPLE_NONCE_EXTENSION_OID: &str = "1.2.840.113635.100.8.2";
const FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;
const APP_ATTEST_DEVELOPMENT_AAGUID: [u8; 16] = *b"appattestdevelop";
const APP_ATTEST_PRODUCTION_AAGUID: [u8; 16] = [
    b'a', b'p', b'p', b'a', b't', b't', b'e', b's', b't', 0, 0, 0, 0, 0, 0, 0,
];

#[derive(Debug, Deserialize)]
struct AppAttestationObject {
    /// App Attest 对象格式标识，真实值应为 `apple-appattest`。
    fmt: String,
    /// 证明语句，包含证书链 `x5c` 和可选的 fraud receipt。
    #[serde(rename = "attStmt")]
    att_stmt: AppAttestationStatement,
    /// WebAuthn 风格的 authenticator data，里面包含 rpIdHash、计数器、credentialId、公钥等。
    #[serde(rename = "authData")]
    auth_data: ByteBuf,
}

#[derive(Debug, Deserialize)]
struct AppAttestationStatement {
    /// 证明证书链，通常第一个是叶子证书，后面是中间证书。
    x5c: Vec<ByteBuf>,
    /// Apple 返回的可选 fraud receipt，可用于后续风险校验。
    #[serde(default)]
    receipt: Option<ByteBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AppAttestEnvironment {
    Development,
    Production,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    /// 已解码的 keyId，通常等于 attested 公钥的哈希。
    pub key_id: Vec<u8>,
    /// App Attest 计数器。首次 attestation 时应为 0，后续 assertion 会递增。
    pub counter: u32,
    /// 当前证明对应的环境，区分 development / production。
    pub environment: AppAttestEnvironment,
    /// 可选的 Apple fraud receipt 原始字节。
    pub receipt: Option<Vec<u8>>,
    /// 叶子证书中的公钥，SPKI DER 编码，适合服务端存储和验签。
    pub public_key_spki_der: Vec<u8>,
    /// 未压缩 EC 公钥，格式为 `04 || X || Y`。
    pub public_key_raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParsedAttestationObjectView {
    /// 顶层格式字段，正常应为 `apple-appattest`。
    pub fmt: String,
    /// `x5c` 证书链数量。
    pub certificate_count: usize,
    /// 是否带有 fraud receipt。
    pub receipt_present: bool,
    /// `authData` 的完整十六进制表示，便于调试原始内容。
    pub auth_data_hex: String,
    /// `rpIdHash = SHA256(app_id)`，用于绑定 Team ID + Bundle ID。
    pub rp_id_hash_hex: String,
    /// `authData` flags 字节，App Attest 一般至少包含 attested credential data 标志。
    pub flags: u8,
    /// 计数器，首次 attestation 为 0。
    pub counter: u32,
    /// 从 AAGUID 推断出的环境。
    pub environment: AppAttestEnvironment,
    /// credentialId 的十六进制形式，通常与你拿到的 keyId 解码值一致。
    pub credential_id_hex: String,
    /// credentialId 的 Base64 形式，便于和客户端的 `keyId` 直接比对。
    pub credential_id_base64: String,
    /// `authData` 中携带的原始公钥，未压缩点格式 `04 || X || Y`。
    pub public_key_raw_hex: String,
    /// 叶子证书公钥的 SPKI DER 十六进制表示。
    pub public_key_spki_der_hex: String,
    /// 叶子证书公钥的 SPKI DER Base64 表示，便于服务端保存。
    pub public_key_spki_der_base64: String,
    /// `authData` 里的公钥是否与叶子证书公钥一致。
    pub public_key_matches_certificate: bool,
    /// 对 raw 公钥做 SHA-256 后得到的十六进制值，通常等于 keyId。
    pub key_id_from_public_key_raw_hex: String,
    /// 对 raw 公钥做 SHA-256 后得到的 Base64 值，通常等于客户端 `keyId`。
    pub key_id_from_public_key_raw_base64: String,
    /// 对 SPKI DER 公钥做 SHA-256 后得到的十六进制值。
    pub key_id_from_public_key_spki_hex: String,
    /// 对 SPKI DER 公钥做 SHA-256 后得到的 Base64 值。
    pub key_id_from_public_key_spki_base64: String,
}

#[derive(Debug)]
struct ParsedAuthenticatorData {
    /// `SHA256(app_id)`，用于校验当前证明绑定到了哪个 App ID。
    rp_id_hash: [u8; 32],
    /// WebAuthn flags 字节。
    flags: u8,
    /// 计数器。
    counter: u32,
    /// AAGUID，用于区分 development / production。
    aaguid: [u8; 16],
    /// 凭证 ID，即 credentialId。
    credential_id: Vec<u8>,
    /// `authData` 里携带的 credential public key，已转换成未压缩 EC 点格式。
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

    let environment = parse_environment(&auth_data.aaguid)?;

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

pub fn parse_attestation_object_base64(
    attestation_object_base64: &str,
) -> Result<ParsedAttestationObjectView> {
    let attestation_object = STANDARD
        .decode(attestation_object_base64)
        .map_err(|err| anyhow!("failed to base64 decode App Attest object: {err}"))?;
    parse_attestation_object_bytes(&attestation_object)
}

pub fn parse_attestation_object_bytes(raw: &[u8]) -> Result<ParsedAttestationObjectView> {
    let object = parse_attestation_object(raw)?;
    if object.fmt != APPLE_APP_ATTEST_FORMAT {
        bail!("unexpected App Attest format {}", object.fmt);
    }
    if object.att_stmt.x5c.is_empty() {
        bail!("App Attest attestation statement is missing x5c certificates");
    }

    let auth_data = parse_authenticator_data(object.auth_data.as_slice())?;
    let environment = parse_environment(&auth_data.aaguid)?;

    let leaf = X509::from_der(&object.att_stmt.x5c[0])?;
    let cert_public_key = leaf.public_key()?;
    let public_key_raw = public_key_raw_bytes(&cert_public_key)?;
    let public_key_spki_der = cert_public_key.public_key_to_der()?;
    let key_id_from_public_key_raw = sha256_bytes(&public_key_raw);
    let key_id_from_public_key_spki = sha256_bytes(&public_key_spki_der);

    Ok(ParsedAttestationObjectView {
        fmt: object.fmt,
        certificate_count: object.att_stmt.x5c.len(),
        receipt_present: object.att_stmt.receipt.is_some(),
        auth_data_hex: hex::encode(object.auth_data.as_slice()),
        rp_id_hash_hex: hex::encode(auth_data.rp_id_hash),
        flags: auth_data.flags,
        counter: auth_data.counter,
        environment,
        credential_id_hex: hex::encode(&auth_data.credential_id),
        credential_id_base64: STANDARD.encode(&auth_data.credential_id),
        public_key_raw_hex: hex::encode(&auth_data.credential_public_key_raw),
        public_key_spki_der_hex: hex::encode(&public_key_spki_der),
        public_key_spki_der_base64: STANDARD.encode(&public_key_spki_der),
        public_key_matches_certificate: auth_data.credential_public_key_raw == public_key_raw,
        key_id_from_public_key_raw_hex: hex::encode(&key_id_from_public_key_raw),
        key_id_from_public_key_raw_base64: STANDARD.encode(&key_id_from_public_key_raw),
        key_id_from_public_key_spki_hex: hex::encode(&key_id_from_public_key_spki),
        key_id_from_public_key_spki_base64: STANDARD.encode(&key_id_from_public_key_spki),
    })
}

pub fn extract_attested_public_key_base64(attestation_object_base64: &str) -> Result<String> {
    Ok(parse_attestation_object_base64(attestation_object_base64)?.public_key_spki_der_base64)
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

fn parse_environment(aaguid: &[u8; 16]) -> Result<AppAttestEnvironment> {
    match *aaguid {
        APP_ATTEST_DEVELOPMENT_AAGUID => Ok(AppAttestEnvironment::Development),
        APP_ATTEST_PRODUCTION_AAGUID => Ok(AppAttestEnvironment::Production),
        other => bail!("unexpected App Attest AAGUID {}", hex::encode(other)),
    }
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

#[derive(Deserialize)]
pub struct RealWorldSample {
    /// 客户端 `generateKey()` 返回的 keyId。
    #[serde(rename = "keyId")]
    key_id: String,
    /// 业务层自定义 clientData JSON 字符串。
    #[serde(rename = "clientDataUtf8")]
    client_data_utf8: String,
    /// `SHA256(clientDataUtf8)` 的 Base64。
    #[serde(rename = "clientDataHashBase64")]
    client_data_hash_base64: String,
    /// Apple 返回的 attestation object，CBOR 二进制后再 Base64。
    #[serde(rename = "attestationObjectBase64")]
    attestation_object_base64: String,
}

pub fn verify_attestation(client_data_utf8: &str, attestation_object_base64: &str) -> Result<()> {
    todo!()
}

impl RealWorldSample {
    pub fn pubkey(&self) -> Result<String> {
        extract_attested_public_key_base64(&self.attestation_object_base64)
    }

    pub fn verify(&self) -> Result<()> {
        let expected_client_data_hash = sha256_bytes(self.client_data_utf8.as_bytes());
        let provided_client_data_hash = self.client_data_hash_base64.decode_bs64()?;
        //todo: replace assert with error
        assert_eq!(provided_client_data_hash, expected_client_data_hash);
        let attestation_object = self.attestation_object_base64.decode_bs64()?;

        let verified = verify_attestation(
            &attestation_object,
            REAL_SAMPLE_APP_ID,
            &self.key_id,
            &provided_client_data_hash,
            APPLE_APP_ATTEST_ROOT_CA_PEM.as_bytes(),
        )?;

        assert_eq!(verified.environment, AppAttestEnvironment::Development);
        assert_eq!(verified.counter, 0);
        assert!(verified.receipt.is_some());
        assert_eq!(verified.key_id, self.key_id.decode_bs64()?);
        Ok(())
    }
    pub fn app_id(&self) -> Result<String> {
        let attestation_object = self.attestation_object_base64.decode_bs64()?;
        let object = parse_attestation_object(&attestation_object)?;
        if object.att_stmt.x5c.is_empty() {
            bail!("App Attest attestation statement is missing x5c certificates");
        }

        let auth_data = parse_authenticator_data(object.auth_data.as_slice())?;
        let candidates = extract_app_id_candidates(&object.att_stmt.x5c[0]);
        let matched = candidates.into_iter().find(|candidate| {
            sha256_bytes(candidate.as_bytes()).as_slice() == auth_data.rp_id_hash.as_slice()
        });

        matched.ok_or_else(|| anyhow!("failed to derive App Attest app id from attestation"))
    }
}

fn extract_app_id_candidates(raw: &[u8]) -> Vec<String> {
    let mut candidates = Vec::new();
    let text = String::from_utf8_lossy(raw);
    let bytes = text.as_bytes();
    let mut start = None;

    for (idx, byte) in bytes.iter().enumerate() {
        let is_allowed = byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_');
        if is_allowed {
            if start.is_none() {
                start = Some(idx);
            }
            continue;
        }

        if let Some(begin) = start.take() {
            if let Some(candidate) = normalize_app_id_candidate(&text[begin..idx]) {
                if !candidates.iter().any(|existing| existing == &candidate) {
                    candidates.push(candidate);
                }
            }
        }
    }

    if let Some(begin) = start {
        if let Some(candidate) = normalize_app_id_candidate(&text[begin..]) {
            if !candidates.iter().any(|existing| existing == &candidate) {
                candidates.push(candidate);
            }
        }
    }

    candidates
}

fn normalize_app_id_candidate(raw: &str) -> Option<String> {
    let trimmed = raw.trim_matches('.');
    let dot_count = trimmed.bytes().filter(|byte| *byte == b'.').count();
    let looks_like_bundle = dot_count >= 2 && trimmed.chars().any(|ch| ch.is_ascii_alphabetic());
    if looks_like_bundle {
        Some(trimmed.to_string())
    } else {
        None
    }
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

    mod verify_attestation_cases {
        use super::*;

        #[test]
        fn accepts_valid_development_attestation() -> Result<()> {
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
        fn rejects_wrong_app_id() -> Result<()> {
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

        #[test]
        fn accepts_real_world_sample() -> Result<()> {
            let sample: RealWorldSample = serde_json::from_str(include_str!(
                "../testdata/ios_real_world_attestation_object.txt"
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

            assert_eq!(verified.environment, AppAttestEnvironment::Development);
            assert_eq!(verified.counter, 0);
            assert!(verified.receipt.is_some());
            assert_eq!(verified.key_id, STANDARD.decode(&sample.key_id)?);
            Ok(())
        }
    }

    mod parse_attestation_object_cases {
        use super::*;

        #[test]
        fn extracts_real_world_public_key() -> Result<()> {
            let sample: RealWorldSample = serde_json::from_str(include_str!(
                "../testdata/ios_real_world_attestation_object.txt"
            ))?;
            let client_data_hash = STANDARD.decode(&sample.client_data_hash_base64)?;
            let attestation_object = STANDARD.decode(&sample.attestation_object_base64)?;

            let parsed = parse_attestation_object_base64(&sample.attestation_object_base64)?;
            let verified = verify_attestation(
                &attestation_object,
                REAL_SAMPLE_APP_ID,
                &sample.key_id,
                &client_data_hash,
                APPLE_APP_ATTEST_ROOT_CA_PEM.as_bytes(),
            )?;

            assert_eq!(parsed.fmt, APPLE_APP_ATTEST_FORMAT);
            assert_eq!(parsed.environment, AppAttestEnvironment::Development);
            assert_eq!(parsed.counter, 0);
            assert_eq!(parsed.credential_id_base64, sample.key_id);
            assert!(parsed.public_key_matches_certificate);
            assert_eq!(
                parsed.public_key_raw_hex,
                hex::encode(&verified.public_key_raw)
            );
            assert_eq!(
                parsed.public_key_spki_der_base64,
                STANDARD.encode(&verified.public_key_spki_der)
            );
            assert_eq!(parsed.key_id_from_public_key_raw_base64, sample.key_id);

            Ok(())
        }

        #[test]
        fn extract_attested_public_key_matches_verified_public_key() -> Result<()> {
            let sample: RealWorldSample = serde_json::from_str(include_str!(
                "../testdata/ios_real_world_attestation_object.txt"
            ))?;
            let client_data_hash = STANDARD.decode(&sample.client_data_hash_base64)?;
            let attestation_object = STANDARD.decode(&sample.attestation_object_base64)?;
            let verified = verify_attestation(
                &attestation_object,
                REAL_SAMPLE_APP_ID,
                &sample.key_id,
                &client_data_hash,
                APPLE_APP_ATTEST_ROOT_CA_PEM.as_bytes(),
            )?;

            let extracted = extract_attested_public_key_base64(&sample.attestation_object_base64)?;
            println!("{}", extracted);
            assert_eq!(extracted, STANDARD.encode(&verified.public_key_spki_der));
            Ok(())
        }

        #[test]
        fn extracts_real_world_app_id() -> Result<()> {
            let sample: RealWorldSample = serde_json::from_str(include_str!(
                "../testdata/ios_real_world_attestation_object.txt"
            ))?;

            assert_eq!(sample.app_id()?, REAL_SAMPLE_APP_ID);
            Ok(())
        }
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
