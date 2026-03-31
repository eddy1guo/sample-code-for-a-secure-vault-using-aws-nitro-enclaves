use std::str::FromStr;

use anyhow::Result;
use ed25519_dalek::{Signer as DalekSigner, Verifier};
use rand::rngs::OsRng;

use crate::codec::bs58::{DecodeBs58, EncodeBs58};
use crate::codec::hex::DecodeHex;

pub fn new_key_pair() -> (String, String) {
    let mut csprng = OsRng {};
    let key_pair = ed25519_dalek::Keypair::generate(&mut csprng);
    let prikey = key_pair.secret.as_bytes().encode_bs58();
    let pubkey: String = key_pair.public.as_bytes().encode_bs58();
    let prikey = format!("{}{}", prikey, pubkey);
    (prikey, pubkey)
}

pub fn sign(prikey: &str, data: &[u8]) -> Result<String> {
    let prikey_bytes = prikey.decode_bs58()?;
    let secret_key = ed25519_dalek::Keypair::from_bytes(&prikey_bytes)?;
    let sig = secret_key.sign(data).to_bytes().encode_bs58();
    Ok(sig)
}

pub fn verify(data: &str, pubkey_hex: &str, sig: &str) -> Result<bool> {
    let public_key_bytes = pubkey_hex.decode_bs58()?;
    let public_key = ed25519_dalek::PublicKey::from_bytes(&public_key_bytes)?;
    let signature = ed25519_dalek::Signature::from_str(sig)?;
    if public_key.verify(data.as_bytes(), &signature).is_ok() {
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_crypto_ed25519() -> Result<()> {
        let (prikey, pubkey) = new_key_pair();
        let input_hex = "hello";
        let sig = sign(&prikey, input_hex.as_bytes())?;
        let verify_res = verify(input_hex, &pubkey, &sig)?;
        assert!(verify_res);
        Ok(())
    }
}
