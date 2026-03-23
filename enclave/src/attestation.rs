use anyhow::{Result, anyhow};
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct CoseSign1Doc {
    pub protected: Vec<u8>,
    pub payload: AttestationDoc,
    pub signature: Vec<u8>,
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

/// Generate an attestation document from NSM with optional user_data binding.
/// The returned bytes are a COSE_Sign1 structure (CBOR encoded), signed by AWS.
pub fn get_attestation_document(user_data: Option<&[u8]>) -> Result<CoseSign1Doc> {
    // #[cfg(not(target_env = "musl"))]
    // {
    //     return Err(anyhow!("NSM not available outside enclave"));
    // }

    // #[cfg(target_env = "musl")]

    let nsm_fd = driver::nsm_init();
    let request = Request::Attestation {
        user_data: user_data.map(|d| ByteBuf::from(d.to_vec())),
        nonce: None,
        public_key: None,
    };
    match driver::nsm_process_request(nsm_fd, request) {
        Response::Attestation { document } => {
            let cose_sign1 = parse_cose_sign1(&document)?;
            //verify_attestation(&cose_sign1)?;
            println!("cose_sign1: {:?}", cose_sign1);
            // 把字节打印成ascii字符串
            println!(
                "cose_sign1.payload.user_data: {}",
                String::from_utf8_lossy(&cose_sign1.payload.user_data.as_ref().unwrap())
            );
            Ok(cose_sign1)
        }
        Response::Error(code) => Err(anyhow!("NSM attestation failed: {:?}", code)),
        other => Err(anyhow!("unexpected NSM response: {:?}", other)),
    }
}

fn parse_cose_sign1(raw: &[u8]) -> Result<CoseSign1Doc> {
    let arr: Vec<serde_cbor::Value> = serde_cbor::from_slice(raw)?;
    let to_bytes = |v: &serde_cbor::Value| match v {
        serde_cbor::Value::Bytes(b) => Ok(b.clone()),
        _ => Err(anyhow!("expected bytes")),
    };

    let protected = to_bytes(&arr[0])?;
    let payload_bytes = to_bytes(&arr[2])?;
    let signature = to_bytes(&arr[3])?;
    let payload: AttestationDoc = serde_cbor::from_slice(&payload_bytes)?;

    Ok(CoseSign1Doc {
        protected,
        payload,
        signature,
    })
}

//todo: verify the attestation document
// use aws_nitro_enclaves_cose::CoseSign1;
// pub fn verify_attestation(cose_bytes: &[u8], expected_pcrs: &BTreeMap<u32, Vec<u8>>) -> Result<AttestationDoc> {
//     // 1. 解析 COSE_Sign1
//     let cose = CoseSign1::from_bytes(cose_bytes)?;
//     let doc: AttestationDoc = serde_cbor::from_slice(cose.get_payload(None)?)?;

//     // 2. 验证证书链 → AWS Root CA
//     let cert = X509::from_der(&doc.certificate)?;
//     verify_cert_chain(&cert, &doc.cabundle)?;

//     // 3. 用叶子证书验签
//     let public_key = cert.public_key()?;
//     cose.verify_signature(&public_key)?;

//     // 4. 验证 PCR 值
//     for (idx, expected) in expected_pcrs {
//         let actual = doc.pcrs.get(idx).ok_or(anyhow!("missing PCR{}", idx))?;
//         if actual.as_slice() != expected.as_slice() {
//             return Err(anyhow!("PCR{} mismatch", idx));
//         }
//     }

//     Ok(doc)
// }

// fn verify_cert_chain(leaf: &X509, cabundle: &[ByteBuf]) -> Result<()> {
//     let mut store_builder = openssl::x509::store::X509StoreBuilder::new()?;
//     // 添加 AWS Nitro Root CA
//     store_builder.add_cert(X509::from_pem(AWS_NITRO_ROOT_CA_PEM)?)?;
//     // 添加中间证书
//     let mut chain = openssl::stack::Stack::new()?;
//     for ca in cabundle {
//         chain.push(X509::from_der(ca)?)?;
//     }
//     let store = store_builder.build();
//     let mut ctx = openssl::x509::X509StoreContext::new()?;
//     ctx.init(&store, leaf, &chain, |c| c.verify_cert())?;
//     Ok(())
// }
