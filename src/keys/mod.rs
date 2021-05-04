// use arrayref::array_ref;
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
// use chacha20poly1305::Key;
use crate::error::Error;
use serde::{Serialize, Deserialize};
// use std::{convert::{TryInto, TryFrom}, fmt::Debug, rc::Rc};


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

// pub(crate) trait KeriSecretKey {
//     fn into_bytes(&self) -> Vec<u8>;
// }

// pub(crate) fn try_vk_from_vec(slice: Vec<u8>) -> Result<Rc<dyn KeriVerifyingKey>, Error> {
//     match &slice.len() {
//         33 => Ok(Rc::new(JwkEcKey::from(K256PublicKey::from(VerifyingKey::from_sec1_bytes(&slice)?)))),
//         _ => Ok(Rc::new(PublicKey::from_bytes(&slice)?))
//     }
// }

// #[cfg(test)]
// pub(crate) fn sk_try_from_secret(other: Rc<dyn KeriSecretKey>) -> Result<Rc<dyn KeriSignerKey>, Error> {
//     match SigningKey::from_bytes(&other.into_bytes()) {
//         Ok(key) => Ok(Rc::new(key)),
//         Err(_) => Ok(Rc::new(SecretKey::from_bytes(&other.into_bytes())?))
//     }
// }

// pub trait KeriSignerKey {
//     fn into_bytes(&self) -> Vec<u8>;
//     fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
//         match SigningKey::from_bytes(&self.into_bytes()) {
//             Ok(k) => {
//                 let sig: EcdsaSignature = EcdsaSigner::sign(&k, msg);
//                 Ok(sig.as_ref().to_vec())
//             },
//             Err(_) => {
//                 let sk = SecretKey::from_bytes(&self.into_bytes())?;
//                 let pk = PublicKey::from(&sk);
//                 Ok(ExpandedSecretKey::from(&sk)
//                     .sign(msg, &pk).as_ref().to_vec())
//             }
//         }
//     }
// }

// impl KeriSignerKey for SigningKey {
//     fn into_bytes(&self) -> Vec<u8> {
//         self.to_bytes().to_vec()
//     }
// }

// impl KeriSignerKey for SecretKey {
//     fn into_bytes(&self) -> Vec<u8> {
//         self.as_bytes().to_vec()
//     }
// }
// pub trait KeriVerifyingKey: Debug + serde_traitobject::Serialize + serde_traitobject::Deserialize {
//     fn into_bytes(&self) -> Vec<u8>;
//     fn verify(&self, msg: &[u8], signature: &[u8]) -> bool {
//         match PublicKey::from_bytes(&self.into_bytes()) {
//             Ok(k) => {
//                 if signature.len() != 64 { return false; }
//                 let sig = Signature::new(array_ref!(signature, 0, 64).to_owned());
//                 Verifier::verify(&k, msg, &sig).is_ok()
//             }   ,
//             Err(_) => match JwkEcKey::verify(self.try_into()?, msg, signature) {
//                 Ok(k) => k,
//                 Err(_) => false
//             }
//             // VerifyingKey::from_sec1_bytes(&self.into_bytes()) {
//             // Ok(k) => {
//             //     if let Ok(sig) = EcdsaSignature::try_from(signature) {
//             //         EcdsaVerifier::verify(&k, msg, &sig).is_ok()
//             //     } else { false }
//             // },
//             // }
//         }
//     }
// }

// impl KeriSecretKey for SigningKey {
//     fn into_bytes(&self) -> Vec<u8> {
//         self.to_bytes().to_vec()
//     }
// }
// impl KeriSecretKey for SecretKey {
//     fn into_bytes(&self) -> Vec<u8> {
//         self.to_bytes().to_vec()
//     }
// }
// impl KeriSecretKey for Key {
//     fn into_bytes(&self) -> Vec<u8> {
//         self.into_iter().map(|b| *b).collect()
//     }
// }

// impl TryInto<Box<dyn KeriSignerKey>> for Box<dyn KeriSecretKey> {
//     type Error = Error;
//     fn try_into(self) -> Result<Box<dyn KeriSignerKey>, Self::Error> {
//         match SigningKey::from_bytes(&self.into_bytes()) {
//             Ok(key) => Ok(Box::new(key)),
//             Err(_) => Ok(Box::new(SecretKey::from_bytes(&self.into_bytes())?))
//         }
//     }
// }

// impl KeriVerifyingKey for PublicKey {
//     fn into_bytes(&self) -> Vec<u8> {
//         self.to_bytes().to_vec()
//     }
// }

// impl KeriVerifyingKey for JwkEcKey {
//     fn into_bytes(&self) -> Vec<u8> {
//         VerifyingKey::from(
//             K256PublicKey::from_jwk(&self).unwrap() // TODO: no unwrap
//         ).to_bytes().to_vec()
//     }
// }
