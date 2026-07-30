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
        let assertion_object_base64 = "omlzaWduYXR1cmVYRjBEAiBfF+Xj7l+5r4LaUdQGLPSf/l64lT/Hng9CcxzynNXZUQIgYVKoDFI4LOSIIH7QIY1aZVXF7fpSEhc+La2Tp4tibglxYXV0aGVudGljYXRvckRhdGFYJcSzS2LHpNtx7epatecV/d7bs/CZi/FoN3vm2i52ysZRQAAAAAU=";
        let pubkey_base64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELIOS3ujBAc4y+BKTwghFlOi3C+tHw/m3r7d0Ekdv8r7521tVIwLyMszRhbIo+smmK1XU+gLdTIauBvhzAY36eA==";
        let payload = r#"{"type":"ConfirmWalletKey","message":"bcc40b3c10627049a886a881165ae606e3b069f5204c9d3f0b3a266647c0fc02f7aad292e8a0d562d233e874ddb4bab989685f2d86654ab66d718adb670ad2eabad61973dfed791a485b2f2cffa8ef7d173ac4f235bc22103ed2bcd88ac72a81175494cf230240f96f1df30c3dac7226abf192c4c6708982486b975b7d210f0a5f35922400b8c256c3cadc4bb81353c3110b0ca671a489f902b7c595632515ea459fc5cf3ace6fbd8930884fce6b5c709d8ba1b0da2c458f7ea27bec0846950df9c32024ea5a77aef3bd2c46e8def09082b3fd4765da335bab3839cf9dffb2466bbb7f9ed1ecffe7d35cfef142ec46f371392afdc64157472cf3b2249f73e62d736ab854868f062451aaf6ee2aac634aec52be3bff23e7e0ddb9b65f19059a3839ca8f728ea4991b55e127470b58074fe981f8848823d52f37635c24672ac333b1250bd4bcf20e8d420b6f0e26004bf43ea527689c0350f90c24eeb5aa91550f29780f5c96526a2d1bdcd08150633481b2904810777151f15c5de2cb8ca8486c082286ee4bd49cdcd650fa4c3a62ea5f1672334934af9aac45d1a69c362e80295fd0b65523a91a17cadd94535949a239af4aa6035d024f903e9d464e1d244b5b95243f307c7101abcf3454de00500440d70d45be517180dcd4"}"#;

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
