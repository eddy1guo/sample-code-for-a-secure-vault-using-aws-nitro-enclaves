use anyhow::{Result, anyhow, bail};
use aws_nitro_enclaves_cose::CoseSign1;
use aws_nitro_enclaves_cose::crypto::Openssl;
use aws_nitro_enclaves_cose::crypto::SigningPublicKey;
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver;
use openssl::pkey::{PKey, Public};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509, X509StoreContext};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;
use std::ops::Not;

#[derive(Debug)]
pub struct CoseSign1Doc {
    pub protected: Vec<u8>,
    pub payload: AttestationDoc,
    pub signature: Vec<u8>,
}

#[derive(Debug)]
pub struct CoseSign1DocView {
    pub protected: String,
    pub payload: AttestationDocView,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct AttestationDoc {
    pub module_id: String,
    pub timestamp: u64,
    pub pcrs: BTreeMap<u32, ByteBuf>,
    pub certificate: ByteBuf,
    pub cabundle: Vec<ByteBuf>,
    #[serde(default)]
    pub user_data: Option<ByteBuf>,
    #[serde(default)]
    pub nonce: Option<ByteBuf>,
    #[serde(default)]
    pub public_key: Option<ByteBuf>,
}

#[derive(Debug, Deserialize)]
pub struct AttestationDocView {
    pub module_id: String,
    pub timestamp: u64,
    pub pcrs: BTreeMap<u32, String>,
    pub certificate: String,
    pub cabundle: Vec<String>,
    #[serde(default)]
    pub user_data: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
}

/// Generate an attestation document from NSM with optional user_data binding.
/// The returned bytes are a COSE_Sign1 structure (CBOR encoded), signed by AWS.
pub fn get_attestation_document(user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    let nsm_fd = driver::nsm_init();
    let request = Request::Attestation {
        user_data: Some(user_data.to_vec().into()),
        nonce: Some(nonce.to_vec().into()),
        public_key: None,
    };
    match driver::nsm_process_request(nsm_fd, request) {
        Response::Attestation { document } => {
            //let cose_sign1 = parse_cose_sign1_view(&document)?;
            //verify_attestation(&cose_sign1)?;
            let doc_hex: String = hex::ToHex::encode_hex(&document);
            println!("cose_hex: {}", doc_hex);
            Ok(document)
        }
        Response::Error(code) => Err(anyhow!("NSM attestation failed: {:?}", code)),
        other => Err(anyhow!("unexpected NSM response: {:?}", other)),
    }
}

fn parse_cose_sign1(raw: &[u8]) -> Result<CoseSign1Doc> {
    let arr: Vec<serde_cbor::Value> = serde_cbor::from_slice(raw)?;
    for (i, v) in arr.iter().enumerate() {
        println!("parse_cose_sign1_value: {} ----> {:?}", i, v);
    }
    let to_bytes = |v: &serde_cbor::Value| match v {
        serde_cbor::Value::Bytes(b) => Ok(b.clone()),
        _ => Err(anyhow!("expected bytes")),
    };

    let protected = to_bytes(&arr[0])?;
    // index 1 is unprotected data， ingore it
    let payload_bytes = to_bytes(&arr[2])?;
    let signature = to_bytes(&arr[3])?;
    let payload: AttestationDoc = serde_cbor::from_slice(&payload_bytes)?;

    Ok(CoseSign1Doc {
        protected,
        payload,
        signature,
    })
}

fn parse_cose_sign1_view(raw: &[u8]) -> Result<CoseSign1DocView> {
    let doc = parse_cose_sign1(raw)?;
    let protected = hex::ToHex::encode_hex(&doc.protected);
    let payload = AttestationDocView {
        module_id: doc.payload.module_id,
        timestamp: doc.payload.timestamp,
        pcrs: doc
            .payload
            .pcrs
            .iter()
            .map(|(k, v)| (*k, hex::ToHex::encode_hex(v)))
            .collect(),
        certificate: hex::ToHex::encode_hex(&doc.payload.certificate),
        cabundle: doc
            .payload
            .cabundle
            .iter()
            .map(|x| (hex::ToHex::encode_hex(x)))
            .collect(),
        user_data: doc
            .payload
            .user_data
            .map(|x| String::from_utf8_lossy(&x).to_string()),
        nonce: doc.payload.nonce.map(|x| hex::ToHex::encode_hex(&x)),
        public_key: doc.payload.public_key.map(|x| hex::ToHex::encode_hex(&x)),
    };
    let signature = hex::ToHex::encode_hex(&doc.signature);

    Ok(CoseSign1DocView {
        protected,
        payload,
        signature,
    })
}

//return user_data
pub fn verify_attestation<T: AsRef<[u8]>>(
    cose_bytes: &[u8],
    expected_pcrs: &BTreeMap<u32, Vec<u8>>,
    client_nonce: &T,
    root_pem: &[u8],
) -> Result<Vec<u8>> {
    // 1. 解析 COSE_Sign1
    let cose = CoseSign1::from_bytes(cose_bytes).unwrap();

    let doc: AttestationDoc = serde_cbor::from_slice(&cose.get_payload::<Openssl>(None).unwrap())?;

    // 2. 验证证书链 → AWS Root CA
    let cert = X509::from_der(&doc.certificate)?;
    verify_cert_chain(&cert, &doc.cabundle, root_pem)?;

    // 3. 用叶子证书验签
    let public_key: PKey<Public> = cert.public_key()?;
    if cose.verify_signature::<Openssl>(&public_key).unwrap().not() {
        bail!("signature verify failed")
    }

    // 4. 验证 PCR 值
    for (idx, expected) in expected_pcrs {
        let actual = doc.pcrs.get(idx).ok_or(anyhow!("missing PCR{}", idx))?;
        if actual.as_slice() != expected.as_slice() {
            return Err(anyhow!("PCR{} mismatch", idx));
        }
    }

    // 5. 验证nonce值
    if doc.nonce.unwrap().as_slice() != client_nonce.as_ref() {
        bail!("nonce mismatch with enclave")
    }

    Ok(doc.user_data.unwrap().to_vec())
}

fn verify_cert_chain(leaf: &X509, cabundle: &[ByteBuf], root_pem: &[u8]) -> Result<()> {
    let mut store_builder = openssl::x509::store::X509StoreBuilder::new()?;
    // 添加 AWS Nitro Root CA
    store_builder.add_cert(X509::from_pem(root_pem)?)?;
    // 添加中间证书
    let mut chain = openssl::stack::Stack::new()?;
    for ca in cabundle {
        chain.push(X509::from_der(ca)?)?;
    }
    let store = store_builder.build();
    let mut ctx = openssl::x509::X509StoreContext::new()?;
    ctx.init(&store, leaf, &chain, |c| c.verify_cert())?;
    Ok(())
}

//todo: testcase: only
#[cfg(test)]
mod tests {
    use super::*;

    const AWS_NITRO_ROOT_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----";

    #[test]
    fn test_doc_verify() -> Result<()> {
        let cose_bytes = hex::decode("")?;

        #[rustfmt::skip]
        let expected_pcrs: BTreeMap<u32,Vec<u8>> = [
            (0,"ad2e856a8ca0b9630813615f8dfdaf8a26ee35e9a8bf14f603de23f27b4f200284f4f0ba33f0efc1eb60473051baa108"),
            (1,"3b4a7e1b5f13c5a1000b3ed32ef8995ee13e9876329f9bc72650b918329ef9cf4e2e4d1e1e37375dab0ba56ba0974d03"),
            (2,"4598202033feb6c58e8759b87c7719090fb74d0b75c360f7b8e26370939df7026dc602a7b4253e000d8b69812b40b790"),
            (8,"ac64413665c4ff2fd4b19fdf8b8ced1d122de075b4bcd00c253183fec32f7a8f4eb0a41c4a3a2282c364c739992aebd3"),
        ].into_iter().map(|(k, v)| (k, hex::decode(v).unwrap())).collect();

        let client_nonce = "abc123";

        let view_doc = parse_cose_sign1_view(&cose_bytes)?;
        println!("{:#?}", view_doc);
        // cose_bytes: &[u8],
        // expected_pcrs: &BTreeMap<u32, Vec<u8>>,
        // client_nonce: &T,
        // root_pem: &[u8],
        let user_data = verify_attestation(
            &cose_bytes,
            &expected_pcrs,
            &client_nonce,
            AWS_NITRO_ROOT_CA_PEM.as_bytes(),
        )?;
        let data_str = String::from_utf8_lossy(&user_data).to_string();
        println!("{}", data_str);
        Ok(())
    }

    #[test]
    fn test_gen_doc_and_verify() -> Result<()> {
        todo!()
    }
}
