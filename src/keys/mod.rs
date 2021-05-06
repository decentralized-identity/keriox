use k256::{
    ecdsa::{    
        SigningKey,
        VerifyingKey,
        Signature as EcdsaSignature,
        signature::{
            Verifier as EcdsaVerifier,
            Signer as EcdsaSigner,
        },
    },
};
use ed25519_dalek::{
    PublicKey,
    SecretKey,
    ExpandedSecretKey,
    Signature
};
use zeroize::Zeroize;
use crate::error::Error;
use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Key {
    key: Vec<u8>
}

impl Key {
    pub fn new(key: Vec<u8>) -> Self {
        Self {
            key
        }
    }

    pub fn verify_ed(&self, msg: &[u8], sig: &[u8]) -> bool {
        if let Ok(key) = PublicKey::from_bytes(&self.key) {
            use arrayref::array_ref;
            if sig.len() != 64 { return false; }
            let sig = Signature::from(array_ref!(sig, 0, 64).to_owned());
            match key.verify(msg, &sig) {
                Ok(()) => true,
                Err(_) => false
            }
        } else {
            false
        }
    }

    pub fn verify_ecdsa(&self, msg: &[u8], sig: &[u8]) -> bool {
        match VerifyingKey::from_sec1_bytes(&self.key) {
            Ok(k) => {
                use k256::ecdsa::Signature;
                use std::convert::TryFrom;
                if let Ok(sig)  = Signature::try_from(sig) {
                    match k.verify(msg, &sig) {
                        Ok(()) => true,
                        Err(_) => false
                    }
                } else {
                    false
                }
            }
            Err(_) => false
        }
    }

    pub fn sign_ecdsa(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let sig: EcdsaSignature = EcdsaSigner::sign(&SigningKey::from_bytes(&self.key)?, msg);
        Ok(sig.as_ref().to_vec())
    }

    pub fn sign_ed(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let sk = SecretKey::from_bytes(&self.key)?;
        let pk = PublicKey::from(&sk);
        Ok(ExpandedSecretKey::from(&sk)
            .sign(msg, &pk).as_ref().to_vec())
    }

    pub fn key(&self) -> Vec<u8> {
        self.key.clone()
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.key.zeroize()
    }
}
