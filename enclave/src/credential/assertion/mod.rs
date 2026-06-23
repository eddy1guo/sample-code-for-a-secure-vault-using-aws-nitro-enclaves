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
    if is_debug_mode()? && assertion_object_base64 == "xxxxxxxx" {
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

    // [enclave:plaintext_pubkey] decrypted wallet key bond payload:
    //
    // WalletKeyBond { user_id: 1002160133, client_platform: Apple, app_id: "F632MRRB47.com.chainlessios.app",
    // master_device_pubkey: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdX0JEw7VFi0q0NlEAZmjc/PyVM5tpf8UuUuV7dxEP16P3rVlBj0S9xXzQhfAPdB/fgjiGzsuqI7Vu3EeAQ99+w==",
    // tee_device_pubkey: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdX0JEw7VFi0q0NlEAZmjc/PyVM5tpf8UuUuV7dxEP16P3rVlBj0S9xXzQhfAPdB/fgjiGzsuqI7Vu3EeAQ99+w==",
    // pwd_pubkey: "7cAdcpVGaaKrDBWA9Xs2n9pFdjNmPToRKP3G6PuEydQ9",
    // wallet_prikey: "ed25519:4XKnC6Lmj3Cw8PETWB1eJA2sasm4SkSYtQNjjqJ4aB7tmehH7wJpn6x8RVNQmGQpfbKoxS13f1pGigir6439fdwk",
    // usage: CreateWalletKey,
    // counter: Some(2) }
    //

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
}
