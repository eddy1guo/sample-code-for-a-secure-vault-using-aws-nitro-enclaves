pub mod apple;
pub mod google;

use anyhow::anyhow;

use crate::{
    codec::bs64::EncodeBs64,
    credential::common::{Platform, sha256_bytes},
};

use crate::credential::aws::is_debug_mode;

pub fn verify_assertion(
    platform: Platform,
    app_id: &str,
    assertion_object_base64: &str,
    pubkey_base64: &str,
    payload: &str,
) -> anyhow::Result<Option<u32>> {
    if assertion_object_base64 == "xxxxxxxx" && is_debug_mode()? {
        return Ok(None);
    }
    match platform {
        Platform::Apple => {
            let msg_hash = sha256_bytes(payload.as_bytes()).encode_bs64();

            apple::verify_assertion_base64(
                assertion_object_base64,
                pubkey_base64,
                &msg_hash,
                app_id,
                None,
            )
            .map(Some)
            .map_err(|e| {
                println!("{:?}", e);
                anyhow!(crate::error::Error::AssertionVerifyFailed.to_json())
            })
        }
        Platform::Google => {
            google::verify_assertion_base64(pubkey_base64, payload, assertion_object_base64)
                .map_err(|e| {
                    println!("{:?}", e);
                    anyhow!(crate::error::Error::AssertionVerifyFailed.to_json())
                })?;
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_platform_apple_assertion() -> anyhow::Result<()> {
        let platform = Platform::Apple;
        let app_id = "F632MRRB47.com.chainlessios.app";
        let assertion_object_base64 = "omlzaWduYXR1cmVYRjBEAiBpaFe765MjsRu00SDxziWo/N161xZFX9HdE3AGRlp9eAIgETOIbDjLVU+SSlwrq1R9VHBk6Yo19N93k17Lsx7j+gBxYXV0aGVudGljYXRvckRhdGFYJcSzS2LHpNtx7epatecV/d7bs/CZi/FoN3vm2i52ysZRQAAAAAY=";
        let pubkey_base64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdFa3Ji1JtuB9gPHgZxtTvKEBw9vttdiQgiBKi3Lewp8com3NvApcl536JO6Xootiy0IkWpo9OPn1w0DXhn7Bww==";
        let payload = r#"{"type":"Sign","message":"dmFsaWRhdGVfdGVlX3NlY3VyaXR5X3Bhc3N3b3JkOjE3ODE3NzcyMTY3Njg=","issued_at":1781777216,"nonce":"1781777216768_43108738800a1c337c9af69853c2"}"#;
        let verified = verify_assertion(
            platform,
            app_id,
            assertion_object_base64,
            pubkey_base64,
            payload,
        )?;
        assert!(verified.is_some());
        Ok(())
    }

    #[test]
    fn test_platform_google_assertion1() -> anyhow::Result<()> {
        let platform = Platform::Google;
        let app_id = "com.chainlessandroid.app";
        let assertion_object_base64 = "MEUCIF2Dhrf1VX1cRcmKBOW0HST6mtS0bH0qQpOsIcvextsaAiEAqoz6o9POoEAoiNhIfUe5aoDDGxDjcs20pm+s0oNPSyA=";
        let pubkey_base64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPpc9sOIPPil0Hput6/w9XNqyHG34w8O6VBAyiXcghUVb1gE3LYDb/EaPmpTFzSQNl/NLI0EM8bVETqFvuHZhgQ==";
        let payload = r#"{\"type\":\"CreateWalletKey\",\"issued_at\":1782142087,\"nonce\":\"1782142087492_624347fa842178143df9e7f86c9e\"}"#;
        let payload = r#"{"type":"CreateWalletKey","issued_at":1782142087,"nonce":"1782142087492_624347fa842178143df9e7f86c9e"}"#;

        let verified = verify_assertion(
            platform,
            app_id,
            assertion_object_base64,
            pubkey_base64,
            payload,
        )?;
        Ok(())
    }

    #[test]
    fn test_platform_google_assertion2() -> anyhow::Result<()> {
        let platform = Platform::Google;
        let app_id = "com.chainlessandroid.app";
        let assertion_object_base64 = "MEUCIF2Dhrf1VX1cRcmKBOW0HST6mtS0bH0qQpOsIcvextsaAiEAqoz6o9POoEAoiNhIfUe5aoDDGxDjcs20pm+s0oNPSyA=";
        let pubkey_base64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPpc9sOIPPil0Hput6/w9XNqyHG34w8O6VBAyiXcghUVb1gE3LYDb/EaPmpTFzSQNl/NLI0EM8bVETqFvuHZhgQ==";
        let payload = r#"{\"type\":\"CreateWalletKey\",\"issued_at\":1782142087,\"nonce\":\"1782142087492_624347fa842178143df9e7f86c9e\"}"#;
        let payload = r#"{"type":"CreateWalletKey","issued_at":1782142087,"nonce":"1782142087492_624347fa842178143df9e7f86c9e"}"#;

        let verified = verify_assertion(
            platform,
            app_id,
            assertion_object_base64,
            pubkey_base64,
            payload,
        )?;
        Ok(())
    }

    #[test]
    fn test_platform_google_assertion3() -> anyhow::Result<()> {
        let platform = Platform::Google;
        let app_id = "com.chainlessandroid.app";
        let assertion_object_base64 = "MEYCIQDf2Wa3MvU0ccudtYAcLSm+xZXlmcDF7qsL1LQ+12ySbgIhAKyhtIJkxm+S2YrSbKSz2bxvvKU/YVX2i6FxdvN7Xep3";
        let pubkey_base64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEU36DCPrN+tvpqn5jMl6yUIXquL60LD2PELaDXQouyYSAjXr8VWLQN7Gtt3Z9y3Rds6r38WjHSY0TOLP+r2SjPA==";
        let payload = r#"{"type":"ConfirmTeeDevice","message":"a2339e5824acd4b18492165f6c8f73de02f5d15a57ad2072891afc5c473d4e593c77d414bd04cce707df1b6d12aca805df2455d346c2650153c8090f5602f787ee2c91d1d9a2ebb7b721b4d164a16606d2e835dbb8607e87241867616b647eb817a4470da435c74ea79a1a7396350d3a9bc3e96787fdf0c64f3a6be0cfa75839961a0c3c83179f298843b012cd05d85f29b2297382d76086d37bcd6291355c9baf51a8080d9b54000653c3d639c292132502d17c0a6b94ca62066deb375855b13c9c92fe362249e387886b4e5c8e35a3dfd8bd253b20ab220c5205856e7ef0787f9b68dd363f2558e2b8ef4de8c7b584ea35ecbf455b4cc20e"}"#;

        let verified = verify_assertion(
            platform,
            app_id,
            assertion_object_base64,
            pubkey_base64,
            payload,
        )?;
        Ok(())
    }

    #[test]
    fn test_platform_google_assertion4() -> anyhow::Result<()> {
        let platform = Platform::Google;
        let app_id = "com.chainlessandroid.app";
        let assertion_object_base64 = "";
        let pubkey_base64 = "";
        let payload = r#"{"type":"CreateWalletKey","issued_at":1782142087,"nonce":"1782142087492_624347fa842178143df9e7f86c9e"}"#;

        let verified = verify_assertion(
            platform,
            app_id,
            assertion_object_base64,
            pubkey_base64,
            payload,
        )?;
        Ok(())
    }

    #[test]
    fn test_platform_google_assertion5() -> anyhow::Result<()> {
        //user_id: 1002160555
        let platform = Platform::Apple;
        let app_id = "F632MRRB47.com.chainlessios.app";
        let assertion_object_base64 = "MEQCICTOpmKt9FgmKNcwIRSH2R2MlGmlOSKySaaf2A/k4Z39AiA+jRpl0QG02TyJGA44jLPnnhEJp6uphvsG6sK30W53tw==";
        let pubkey_base64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELIOS3ujBAc4y+BKTwghFlOi3C+tHw/m3r7d0Ekdv8r7521tVIwLyMszRhbIo+smmK1XU+gLdTIauBvhzAY36eA==";
        let payload = r#"{"type":"ConfirmWalletKey","message":"987db5742c2468d557b1075cee23c4a95a6a7a000a5190cfd4269b50fc18fe9b304bab7360a8a5bcfb72b1d5573ee038d2fcec0fd2e75f44baea5433aedacbb50f6edb04f30b322f0d1a25e0ec2e17396b36193ffdd7306c9c557e5b1d8cb85013fcdad2ce83e39126893c1742ebaf8ae45f1e9c44ba0d86d1987a8e3eae25a0e220271674e231b02cc8df338da09c78a6b439f84520cd3afa65c596156b6daa17eb0d2fa627cd683ac975cd29f9957ed439459239873ce9aa8818dd532f4d8062e763c32885b047bc794411209f57fd36940b27ef27ce5443562d9a5f93ac6444d7f3e61a2a2c86ba95f2ed4ac3bb9edce8b159343d73c9db2374b23e68cfe6e55c1c707c5a28a7f24ac5b85cd9dbc59168c2141a617ad31ca44f454ea53739577a8f08da3a6cc7410cb8bcc375c792dac9906fb2136cb4ddd3e306f74a161f254ea0fbadfa075a82157cd3b4590ba9e6f85ab3c9a2543ee6db24db71fe321a5fb34f86f502c684e5158a27c652a581f62266e645216544edf88a792c74568e43fc7c719f17afeaa291b97dbf94a8b1bf280035e7561de547057fb9c94963e12a3d8c545d7ba929c32c83ccc6fed799ef1d9570b0d866702ce257ed2b9e749e169f97bc7c6cc4e7ac1fad0a584cf632b6dafba439248150dcefa9e8c717800bf0e6"}"#;

        let verified = verify_assertion(
            platform,
            app_id,
            assertion_object_base64,
            pubkey_base64,
            payload,
        )?;
        Ok(())
    }

    #[test]
    fn test_platform_google_assertion6() -> anyhow::Result<()> {
        let platform = Platform::Google;
        let app_id = "com.chainlessandroid.app";
        let assertion_object_base64 = "MEYCIQC/w905raE9zxSCUrkj2v5If86zAz8OrGPBZQ4g6qY4swIhAMF1R+5TkieBAZ3PDXW6fJ1tkO4bqNNSUG6EosVGXaU/";
        let pubkey_base64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiXEnJqrescl4RDYZdER2sQ+kc6+YcjlJPCI7J79juq/XAyj5QVAqbf8A7TBcSFRsxYEYOMKxdVuOy2bgkAoBOQ==";
        //  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERoMqb7yeQBJRA73ryjfvDMcQ6bRmNVqnwS1C8IdVnN9MoYVQFiqPfi01g20n8b9XP5kp8tcYk23cefs1bEIc7A==
        let pubkey_base64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERoMqb7yeQBJRA73ryjfvDMcQ6bRmNVqnwS1C8IdVnN9MoYVQFiqPfi01g20n8b9XP5kp8tcYk23cefs1bEIc7A==";

        let payload = r#"{"type":"Sign","message":"q/wKT6Uc28KN9EfE7heJSDag1tYYFab3yPTQi8NFc6A=","issued_at":1785076589,"nonce":"1785076589812_7c7f9deb972c54efb4b57c19b408"}"#;

        let verified = verify_assertion(
            platform,
            app_id,
            assertion_object_base64,
            pubkey_base64,
            payload,
        )?;
        Ok(())
    }
}
