use anyhow::{Result, anyhow, bail};
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver;
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

//todo: testcase: only
#[cfg(test)]
mod tests {
    use super::*;
    use aws_nitro_enclaves_cose::CoseSign1;
    use aws_nitro_enclaves_cose::crypto::Openssl;
    use aws_nitro_enclaves_cose::crypto::SigningPublicKey;
    use openssl::pkey::{PKey, Public};
    use openssl::stack::Stack;
    use openssl::x509::store::X509StoreBuilder;
    use openssl::x509::{X509, X509StoreContext};
    //ref: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
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

    //return user_data
    pub fn verify_attestation<T: AsRef<[u8]>>(
        cose_bytes: &[u8],
        expected_pcrs: &BTreeMap<u32, Vec<u8>>,
        client_nonce: &T,
        root_pem: &[u8],
    ) -> Result<Vec<u8>> {
        // 1. 解析 COSE_Sign1
        let cose = CoseSign1::from_bytes(cose_bytes).unwrap();

        let doc: AttestationDoc =
            serde_cbor::from_slice(&cose.get_payload::<Openssl>(None).unwrap())?;

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

    #[test]
    fn test_doc_verify() -> Result<()> {
        let cose_bytes = hex::decode(
            "8444a1013822a0591143bf696d6f64756c655f69647827692d3037393937\
             6137346432656362333866312d656e633031396431663961633833323662\
             333966646967657374665348413338346974696d657374616d701b000001\
             9d1fa37cd06470637273b0005830ad59fb9d03b767ea6d0bf78f9f4db324\
             3fb8673af3105278808c61776d4156bd264c21cfe02fddf64548103ea3f3\
             49700158303b4a7e1b5f13c5a1000b3ed32ef8995ee13e9876329f9bc72\
             650b918329ef9cf4e2e4d1e1e37375dab0ba56ba0974d03025830b68644\
             10ed139e6749de18da11a7aa352634ec2dbfd158cefe74c79de7ce6c23fe\
             6f7643270322385cd963978dfcd6d303583076815ed66560762cdeed0a7f\
             4721fdfd17662055b15e31a73e9cf99844b18d2bcd75a269aac7f0b0cdce\
             20d7ad5231b5045830312d493f442cbed4988ff01622421c1e258148b8e9\
             5f5aa5394510d7032777cab0adfe3e0ca38015d91d389c62892ec2055830\
             0000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000006583000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000\
             0000000000000000007583000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000\
             0858309c5c98fdc8ba4a17dca091234dd7ae6f708972bdcdfe83df7b87c3\
             aa57c5e084d5f6e8a84dcaa6d47da9b9aa325ea964095830000000000000\
             0000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000a5830000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000\
             00b58300000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000c583000000000000000\
             0000000000000000000000000000000000000000000000000000000000000\
             00000000000000000000d58300000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000\
             0e5830000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000f5830000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000\
             000000000000000000006b6365727469666963617465590289308202863082\
             020ba0030201020210019d1f9ac8326b390000000069c277ad300a06082a86\
             48ce3d040303308193310b30090603550406130255533113301106035504080\
             c0a57617368696e67746f6e3110300e06035504070c0753656174746c6531\
             0f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533\
             13e303c06035504030c35692d303739393761373464326563623338663132\
             e61702d6e6f727468656173742d312e6177732e6e6974726f2d656e636c61\
             766573301e170d3236303332343131333831385a170d323630333234313433\
             3832315a308198310b30090603550406130255533113301106035504080c0a\
             57617368696e67746f6e3110300e06035504070c0753656174746c65310f30\
             0d060355040a0c06416d617a6f6e310c300a060355040b0c03415753314330\
             4106035504030c3a692d30373939376137346432656362333866312d656e63\
             303139643166396163383332366233392e61702d6e6f727468656173742d31\
             2e6177733076301006072a8648ce3d020106052b8104002203620004251c38\
             edc25f42dd96a2ba5ef4104fa5a7cb9bcea11ca9479d80bf4086f0d7113a3e\
             a6b16ea5cda07281cb795b1f6ae4be7a36c9661dfd6fd709b5beeb139af735\
             0d8f12c17d7af141e22cc1a4b8d647d55e1aeb6e97b9c25bfbc391271c3cc\
             1a31d301b300c0603551d130101ff04023000300b0603551d0f0404030206c0\
             300a06082a8648ce3d04030303690030660231008bc4928282a74ed7fbab481\
             45807500d032ae43011cc87f6d66d0d41906c2d81d068cc4425cd3e41b0d338\
             5113e3162b023100974ca78efd6693d69182e2514c0e3981649719b868c0e03\
             89f1d838ff99c1e7a8474240ee1cb282997c5cf1896b73faf68636162756e64\
             6c65845902153082021130820196a003020102021100f93175681b90afe11d46\
             ccb4e4e7f856300a06082a8648ce3d0403033049310b300906035504061302555\
             3310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533\
             11b301906035504030c126177732e6e6974726f2d656e636c61766573301e170\
             d3139313032383133323830355a170d3439313032383134323830355a3049310b\
             3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a0\
             60355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e\
             636c617665733076301006072a8648ce3d020106052b8104002203620004fc025\
             4eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4\
             b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6f\
             1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4a342304\
             0300f0603551d130101ff040530030101ff301d0603551d0e041604149025b50d\
             d90547e796c396fa729dcf99a9df4b96300e0603551d0f0101ff0404030201863\
             00a06082a8648ce3d0403030369003066023100a37f2f91a1c9bd5ee7b8627c16\
             98d255038e1f0343f95b63a9628c3d39809545a11ebcbf2e3b55d8aeee71b4c3\
             d6adf3023100a2f39b1605b27028a5dd4ba069b5016e65b4fbde8fe0061d6a531\
             97f9cdaf5d943bc61fc2beb03cb6fee8d2302f3dff65902c8308202c43082024a\
             a003020102021100b894a93587f0cf903b4e77e4707084bb300a06082a8648ce3\
             d0403033049310b3009060355040613025553310f300d060355040a0c06416d617\
             a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e\
             6974726f2d656e636c61766573301e170d3236303332313036343834305a170d3\
             236303431303037343834305a3069310b3009060355040613025553310f300d060\
             355040a0c06416d617a6f6e310c300a060355040b0c03415753313b3039060355\
             04030c32633731633964336130333437363631612e61702d6e6f72746865617374\
             2d312e6177732e6e6974726f2d656e636c617665733076301006072a8648ce3d0\
             20106052b8104002203620004e26aa766d4e66c2d69c46b786447108df58fda63\
             77f1645744bbdcf47318919bbc4e20108d6dfaf8e4eef6963fec05c263237de4b\
             6b3beebb8587326eeda65c52c31e15b4f258b83bbe^@671d454d1acd8f20638be33\
             404f442952d77dd3b21e7fa381d53081d230120603551d130101ff04083006010\
             1ff020102301f0603551d230418301680149025b50dd90547e796c396fa729dcf\
             99a9df4b96301d0603551d0e0416041495c5e0c7f28c53183bba57ae156944d8d\
             19e6ed0300e0603551d0f0101ff040403020186306c0603551d1f046530633061\
             a05fa05d865b687474703a2f2f6177732d6e6974726f2d656e636c617665732d6\
             3726c2e73332e616d617a6f6e6177732e636f6d2f63726c2f61623439363063632\
             d376436332d343262642d396539662d3539333338636236376638342e63726c30\
             0a06082a8648ce3d0403030368003065023026b5c6beb5d0f55303c746e35cd0a\
             6541cddb29b4bbe05e8620da324156657cab9539474ac3bff5dc84ff2c6447775\
             d1023100931a40b9d235879b9b120815a6cd1ffbe666ed1821a3340c1645d8810\
             85e6fc119a52911e87d46d6d923074fa4b3c78d59032f3082032b308202b1a003\
             020102021100a17add437d87784038ae8ca3a13d2341300a06082a8648ce3d0403\
             033069310b3009060355040613025553310f300d060355040a0c06416d617a6f6e\
             310c300a060355040b0c03415753313b303906035504030c326337316339643361\
             30333437363631612e61702d6e6f727468656173742d312e6177732e6e6974726f\
             2d656e636c61766573301e170d3236303332343030303434385a170d3233303332\
             393134303434385a30818e3141303f06035504030c38316237333330663863393830\
             663364352e7a6f6e616c2e61702d6e6f727468656173742d312e6177732e6e6974\
             726f2d656e636c61766573310c300a060355040b0c03415753310f300d060355040\
             a0c06416d617a6f6e310b3009060355040613025553310b300906035504080c0257\
             413110300e06035504070c0753656174746c653076301006072a8648ce3d020106\
             052b810400220362000422a8a0a0a341772bbe7ffcb7eaa54c088aefaa81b346b7\
             c393920e822e0a636ab1d68e7645c84978fb8047ae69c8e12bde5493cc3586793c\
             3b5c68b620c3b181eec2809b73456eb14060d9ec35ad8f2dd294a5aac8df4872b6\
             5b979ae90bf1aaa381f63081f330120603551d130101ff040830060101ff020101\
             301f0603551d2304183016801495c5e0c7f28c53183bba57ae156944d8d19e6ed0\
             301d0603551d0e04160414fc2ce4bedd23acf20efd38758c6a580374d7f200300e\
             0603551d0f0101ff04040302018630818c0603551d1f048184308181307fa07da07\
             b8679687474703a2f2f63726c2d61702d6e6f727468656173742d312d6177732d6\
             e6974726f2d656e636c617665732e73332e61702d6e6f727468656173742d312e6\
             16d617a6f6e6177732e636f6d2f63726c2f34346134376263662d306331612d3466\
             36392d393439622d3131323866373738396334662e63726c300a06082a8648ce3d0\
             403030368003065023100ea018a230a227276188ad46dada7879a6ed5736e55fc59\
             5916b712c50c045f303901f0ac7d9ef85a6e1e29d38d8caf25023053312550d6d5\
             d4acaa7a30e8be9fb7603e5738a6da315dcead8186877a0956ece24830512597203\
             563a6c72d8a8ef8615902cc308202c83082024ea0030201020214788d340f72c648\
             0b478dc1363efd8e4135f203e3300a06082a8648ce3d04030330818e3141303f060\
             35504030c38316237333330663863393830663364352e7a6f6e616c2e61702d6e6f\
             727468656173742d312e6177732e6e6974726f2d656e636c61766573310c300a060\
             355040b0c03415753310f300d060355040a0c06416d617a6f6e310b300906035504\
             0613025553310b300906035504080c0257413110300e06035504070c075365617474\
             6c65301e170d3236303332343131323731305a170d3236303332353131323731305a\
             308193310b30090603550406130255533113301106035504080c0a57617368696e67\
             746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d\
             617a6f6e310c300a060355040b0c03415753313e303c06035504030c35692d303739\
             39376137346432656362333866312e61702d6e6f727468656173742d312e6177732e\
             6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b81040022\
             036200046205e2c0606882681a7cd0e37ec9ef33ba287ff83ef14407972ea3341cd7\
             8a914c8b9b5198c51456f74f08bdad96af250eb4c01e57bd4b2041f779050dea8ff\
             33a484f1622168c8526e4f10e9a7316497c99959a035036a5a49f185c75a3232ca3\
             66306430120603551d130101ff040830060101ff020100300e0603551d0f0101ff04\
             0403020204301d0603551d0e04160414775961947696ecbe1328f021bd3d873cef5b\
             addf301f0603551d23041830168014fc2ce4bedd23acf20efd38758c6a580374d7f2\
             00300a06082a8648ce3d04030303680030650230539090f171288951afd8776706e\
             1fd86630132028d9f7339491cb3340266c38535a893304b4fc72b1db0037b6bb9d26\
             02310087202b35b421424bb706417ec28d7ea10e7169c4bf26ffd9f801c380dedd21\
             6faf56407f8a391444bc52a96625be46b76a7075626c69635f6b6579f66975736572\
             5f646174614c746573745f646174615f3033656e6f6e63654661626331323\
             3ff5860057b1ff496a82a5a778616f87022a12f1d43153ae1484cc75e858c6c894e\
             f0ffcf209b7ab0011050f1584cf24da4198e5abd72ef66ae210713128a46444d9ca1\
             35b97aeb0a41f5e97ed98d3c729ee4f44009f1ca19e52ec815f803b88146cc19",
        )?;
        #[rustfmt::skip]
        let expected_pcrs: BTreeMap<u32,Vec<u8>> = [
            (0,"ad59fb9d03b767ea6d0bf78f9f4db3243fb8673af3105278808c61776d4156bd264c21cfe02fddf64548103ea3f34970"),
            (1,"3b4a7e1b5f13c5a1000b3ed32ef8995ee13e9876329f9bc72650b918329ef9cf4e2e4d1e1e37375dab0ba56ba0974d03"),
            (2,"b6864410ed139e6749de18da11a7aa352634ec2dbfd158cefe74c79de7ce6c23fe6f7643270322385cd963978dfcd6d3"),
            (8,"9c5c98fdc8ba4a17dca091234dd7ae6f708972bdcdfe83df7b87c3aa57c5e084d5f6e8a84dcaa6d47da9b9aa325ea964"),
        ].into_iter().map(|(k, v)| (k, hex::decode(v).unwrap())).collect();

        let client_nonce = "abc123";

        //let view_doc = parse_cose_sign1_view(&cose_bytes)?;
        //println!("{:#?}", view_doc);
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
