use anyhow::{Result, bail};
use ed25519_dalek::{PublicKey, SecretKey, Signer as DalekSigner, Verifier};
use openssl::sha::sha256;
use rand::rngs::OsRng;

use crate::codec::bs58::{DecodeBs58, EncodeBs58};

pub fn new_key_pair_by_seed(seed: &str) -> (Vec<u8>, Vec<u8>) {
    assert!(
        seed.len() == 6 && seed.chars().all(|c| c.is_ascii_digit()),
        "seed must be a 6-digit numeric string"
    );

    let secret_seed = sha256(seed.to_string().as_bytes());
    let secret_key = SecretKey::from_bytes(&secret_seed).expect("sha256 output must be 32 bytes");
    let public_key = PublicKey::from(&secret_key);

    let mut prikey = secret_key.as_bytes().to_vec();
    let pubkey = public_key.as_bytes().to_vec();
    prikey.extend(&pubkey);
    (prikey, pubkey)
}

pub fn new_key_pair() -> (Vec<u8>, Vec<u8>) {
    let mut csprng = OsRng {};
    let key_pair = ed25519_dalek::Keypair::generate(&mut csprng);
    let mut prikey = key_pair.secret.as_bytes().to_vec();
    let pubkey = key_pair.public.as_bytes().to_vec();
    prikey.extend(&pubkey);
    (prikey, pubkey)
}

pub fn sign(prikey_bytes: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let secret_key = ed25519_dalek::Keypair::from_bytes(prikey_bytes)?;
    let sig = secret_key.sign(data).to_bytes().to_vec();
    Ok(sig)
}

pub fn verify(data: &str, public_key_bytes: &[u8], sig: &[u8]) -> Result<bool> {
    let public_key = ed25519_dalek::PublicKey::from_bytes(public_key_bytes)?;
    let signature = ed25519_dalek::Signature::from_bytes(sig)?;
    if public_key.verify(data.as_bytes(), &signature).is_ok() {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub trait ExtractPubkey {
    fn extract_pubkey(&self) -> Result<String>;
}

impl ExtractPubkey for String {
    fn extract_pubkey(&self) -> Result<String> {
        let data = self.decode_bs58()?;
        if data.len() != 64 {
            bail!("it's len not equal 64");
        }
        let pubkey = data[32..64].iter().encode_bs58();
        Ok(pubkey)
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

    #[test]
    fn test_new_key_pair_by_seed_is_deterministic() -> Result<()> {
        let (prikey1, pubkey1) = new_key_pair_by_seed("123456");
        let (prikey2, pubkey2) = new_key_pair_by_seed("123456");
        let (_, pubkey3) = new_key_pair_by_seed("654321");

        assert_eq!(prikey1, prikey2);
        assert_eq!(pubkey1, pubkey2);
        assert_ne!(pubkey1, pubkey3);

        let sig = sign(&prikey1, b"hello")?;
        assert!(verify("hello", &pubkey1, &sig)?);
        Ok(())
    }
}
