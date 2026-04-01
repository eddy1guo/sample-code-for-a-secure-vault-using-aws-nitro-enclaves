use std::str::FromStr;

use anyhow::Result;
use ed25519_dalek::{Signer as DalekSigner, Verifier};
use rand::rngs::OsRng;

use crate::codec::bs58::{DecodeBs58, EncodeBs58};
use crate::codec::hex::{DecodeHex, EncodeHex};

pub fn new_key_pair() -> (Vec<u8>, Vec<u8>) {
    let mut csprng = OsRng {};
    let key_pair = ed25519_dalek::Keypair::generate(&mut csprng);
    let mut prikey = key_pair.secret.as_bytes().to_vec();
    let pubkey = key_pair.public.as_bytes().to_vec();
    prikey.extend(&pubkey);
    (prikey, pubkey)
}

pub fn sign(prikey_bytes: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let secret_key = ed25519_dalek::Keypair::from_bytes(&prikey_bytes)?;
    let sig = secret_key.sign(data).to_bytes().to_vec();
    Ok(sig)
}

pub fn verify(data: &str, public_key_bytes: &[u8], sig: &[u8]) -> Result<bool> {
    let public_key = ed25519_dalek::PublicKey::from_bytes(&public_key_bytes)?;
    let signature = ed25519_dalek::Signature::from_bytes(sig)?;
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
