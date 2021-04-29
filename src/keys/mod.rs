use arrayref::array_ref;
use k256::ecdsa::{
    SigningKey,
    VerifyingKey,
    Signature as EcdsaSignature,
    signature::{
        Verifier as EcdsaVerifier,
        Signer as EcdsaSigner,
    },
};
use ed25519_dalek::{
    PublicKey,
    SecretKey,
    ExpandedSecretKey,
    Verifier,
    Signature
};
use chacha20poly1305::Key;
use crate::error::Error;
use std::{convert::TryInto, fmt::Debug, rc::Rc};

pub(crate) trait KeriSecretKey {
    fn into_bytes(&self) -> Vec<u8>;
}
pub(crate) trait KeriPublicKey: Debug {
    fn into_bytes(&self) -> Vec<u8>;
    fn as_bytes(&self) -> &[u8];
}

pub(crate) fn try_pk_from_vec(slice: Vec<u8>) -> Result<Rc<dyn KeriPublicKey>, Error> {
    match &slice.len() {
        33 => Ok(Rc::new(VerifyingKey::from_sec1_bytes(&slice)?)),
        _ => Ok(Rc::new(PublicKey::from_bytes(&slice)?))
    }
}

pub(crate) trait KeriSignerKey {
    fn into_bytes(&self) -> Vec<u8>;
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        match SigningKey::from_bytes(&self.into_bytes()) {
            Ok(k) => {
                let sig: EcdsaSignature = EcdsaSigner::sign(&k, msg);
                Ok(sig.as_ref().to_vec())
            },
            Err(_) => {
                let sk = SecretKey::from_bytes(&self.into_bytes())?;
                let pk = PublicKey::from(&sk);
                Ok(ExpandedSecretKey::from(&sk)
                    .sign(msg, &pk).as_ref().to_vec())
            }
        }
    }
}

impl KeriSignerKey for SigningKey {
    fn into_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

impl KeriSignerKey for SecretKey {
    fn into_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}
pub(crate) trait KeriVerifyingKey: Debug {
    fn into_bytes(&self) -> Vec<u8>;
    fn verify(&self, msg: &[u8], signature: &[u8]) -> bool {
        match VerifyingKey::from_sec1_bytes(&self.into_bytes()) {
            Ok(k) => {
                if let Ok(sig) = EcdsaSignature::from_asn1(signature) {
                    EcdsaVerifier::verify(&k, msg, &sig).is_ok()
                } else { false }
            },
            Err(_) => match PublicKey::from_bytes(&self.into_bytes()) {
                Ok(k) => {
                    if signature.len() != 64 { return false; }
                    let sig = Signature::new(array_ref!(signature, 0, 64).to_owned());
                    Verifier::verify(&k, msg, &sig).is_ok()
            }   ,
                Err(_) => false
            }
        }
    }
}

impl KeriSecretKey for SigningKey {
    fn into_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}
impl KeriSecretKey for SecretKey {
    fn into_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}
impl KeriSecretKey for Key {
    fn into_bytes(&self) -> Vec<u8> {
        self.into_iter().map(|b| *b).collect()
    }
}

impl TryInto<Box<dyn KeriSignerKey>> for Box<dyn KeriSecretKey> {
    type Error = Error;
    fn try_into(self) -> Result<Box<dyn KeriSignerKey>, Self::Error> {
        match SigningKey::from_bytes(&self.into_bytes()) {
            Ok(key) => Ok(Box::new(key)),
            Err(_) => Ok(Box::new(SecretKey::from_bytes(&self.into_bytes())?))
        }
    }
}

pub(crate) fn sk_try_from_secret(other: Rc<dyn KeriSecretKey>) -> Result<Rc<dyn KeriSignerKey>, Error> {
    match SigningKey::from_bytes(&other.into_bytes()) {
        Ok(key) => Ok(Rc::new(key)),
        Err(_) => Ok(Rc::new(SecretKey::from_bytes(&other.into_bytes())?))
    }
}

impl KeriPublicKey for VerifyingKey {
    fn into_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
    fn as_bytes(&self) -> &[u8] {
        &self.to_bytes()
    }
}
impl KeriPublicKey for PublicKey {
    fn into_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
    fn as_bytes(&self) -> &[u8] {
        &self.to_bytes()
    }
}

impl KeriVerifyingKey for PublicKey {
    fn into_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}
impl KeriVerifyingKey for VerifyingKey {
    fn into_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

pub(crate) fn vk_into_pk(other: Rc<dyn KeriVerifyingKey>) -> Rc<dyn KeriPublicKey> {
    match VerifyingKey::from_sec1_bytes(&other.into_bytes()) {
        Ok(key) => Rc::new(key),
        Err(_) => Rc::new(PublicKey::from_bytes(&other.into_bytes()).unwrap())
    }
}

pub(crate) fn pk_into_vk(other: Rc<dyn KeriPublicKey>) -> Rc<dyn KeriVerifyingKey> {
    match VerifyingKey::from_sec1_bytes(&other.into_bytes()) {
        Ok(key) => Rc::new(key),
        Err(_) => Rc::new(PublicKey::from_bytes(&other.into_bytes()).unwrap())
    }
}

impl TryInto<Box<dyn KeriVerifyingKey>> for &dyn KeriPublicKey {
    type Error = Error;
    fn try_into(self) -> Result<Box<dyn KeriVerifyingKey>, Self::Error> {
        match VerifyingKey::from_sec1_bytes(&self.into_bytes()) {
            Ok(key) => Ok(Box::new(key)),
            Err(_) => Ok(Box::new(PublicKey::from_bytes(&self.into_bytes())?))
        }
    }
}

