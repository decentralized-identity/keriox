use crate::error::Error;
use ed25519_dalek::{ExpandedSecretKey, SecretKey};
use k256::ecdsa::{signature::Signer as EcdsaSigner, Signature as EcdsaSignature, SigningKey};
use k256::ecdsa::{signature::Verifier as EcdsaVerifier, VerifyingKey};
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq, Hash)]
pub struct PublicKey {
    public_key: Vec<u8>,
}

impl PublicKey {
    pub fn new(key: Vec<u8>) -> Self {
        PublicKey {
            public_key: key.to_vec(),
        }
    }

    pub fn key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    pub fn verify_ed(&self, msg: &[u8], sig: &[u8]) -> bool {
        if let Ok(key) = ed25519_dalek::PublicKey::from_bytes(&self.key()) {
            use arrayref::array_ref;
            if sig.len() != 64 {
                return false;
            }
            let sig = ed25519_dalek::Signature::from(array_ref!(sig, 0, 64).to_owned());
            match key.verify(msg, &sig) {
                Ok(()) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    }

    pub fn verify_ecdsa(&self, msg: &[u8], sig: &[u8]) -> bool {
        match VerifyingKey::from_sec1_bytes(&self.key()) {
            Ok(k) => {
                use k256::ecdsa::Signature;
                use std::convert::TryFrom;
                if let Ok(sig) = Signature::try_from(sig) {
                    match k.verify(msg, &sig) {
                        Ok(()) => true,
                        Err(_) => false,
                    }
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PrivateKey {
    key: Vec<u8>,
}

impl PrivateKey {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    pub fn sign_ecdsa(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let sig: EcdsaSignature = EcdsaSigner::sign(&SigningKey::from_bytes(&self.key)?, msg);
        Ok(sig.as_ref().to_vec())
    }

    pub fn sign_ed(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let sk = SecretKey::from_bytes(&self.key)?;
        let pk = ed25519_dalek::PublicKey::from(&sk);
        Ok(ExpandedSecretKey::from(&sk)
            .sign(msg, &pk)
            .as_ref()
            .to_vec())
    }

    pub fn key(&self) -> Vec<u8> {
        self.key.clone()
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.key.zeroize()
    }
}

#[test]
fn libsodium_to_ed25519_dalek_compat() {
    use ed25519_dalek::Signature;
    use rand::rngs::OsRng;

    let kp = ed25519_dalek::Keypair::generate(&mut OsRng);

    let msg = b"are libsodium and dalek compatible?";

    let dalek_sig = kp.sign(msg);

    use sodiumoxide::crypto::sign;

    let sodium_pk = sign::ed25519::PublicKey::from_slice(&kp.public.to_bytes());
    assert!(sodium_pk.is_some());
    let sodium_pk = sodium_pk.unwrap();
    let mut sodium_sk_concat = kp.secret.to_bytes().to_vec();
    sodium_sk_concat.append(&mut kp.public.to_bytes().to_vec().clone());
    let sodium_sk = sign::ed25519::SecretKey::from_slice(&sodium_sk_concat);
    assert!(sodium_sk.is_some());
    let sodium_sk = sodium_sk.unwrap();

    let sodium_sig = sign::sign(msg, &sodium_sk);

    assert!(sign::verify_detached(
        &sign::ed25519::Signature::new(dalek_sig.to_bytes()),
        msg,
        &sodium_pk
    ));

    assert!(kp
        .verify(
            msg,
            &Signature::new(arrayref::array_ref!(sodium_sig, 0, 64).to_owned())
        )
        .is_ok());
}
