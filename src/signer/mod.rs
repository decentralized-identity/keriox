use crate::{
    derivation::basic::Basic, derivation::self_signing::SelfSigning, error::Error,
    prefix::AttachedSignaturePrefix, prefix::BasicPrefix,
};
use ursa::{
    keys::{PrivateKey, PublicKey},
    signatures::{ed25519, SignatureScheme},
};

pub struct Signer {
    derivation: Basic,
    current_keypair: (PublicKey, PrivateKey),
    next_keypair: (PublicKey, PrivateKey),
}

impl Signer {
    pub fn new(derivation: Basic) -> Result<Self, Error> {
        let (current_keypair, next_keypair) = match derivation {
            Basic::Ed25519 => {
                let ed = ed25519::Ed25519Sha512::new();
                (
                    ed.keypair(None).map_err(|e| Error::CryptoError(e))?,
                    ed.keypair(None).map_err(|e| Error::CryptoError(e))?,
                )
            }
            _ => {
                todo!();
            }
        };

        Ok(Signer {
            derivation,
            current_keypair,
            next_keypair,
        })
    }

    pub fn public_key(&self) -> BasicPrefix {
        self.derivation.derive(self.current_keypair.0.clone())
    }

    pub fn next_public_key(&self) -> BasicPrefix {
        self.derivation.derive(self.next_keypair.0.clone())
    }

    pub fn sign(&self, msg: Vec<u8>) -> Result<AttachedSignaturePrefix, Error> {
        let signature = match self.derivation {
            Basic::Ed25519 => ed25519::Ed25519Sha512::new()
                .sign(&msg, &self.current_keypair.1)
                .map_err(|e| Error::CryptoError(e))?,
            _ => todo!(),
        };
        Ok(AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        ))
    }

    pub fn rotate(&self) -> Result<Self, Error> {
        let ed = ed25519::Ed25519Sha512::new();
        let new_next_keypair = match self.derivation {
            Basic::Ed25519 => ed.keypair(None).map_err(|e| Error::CryptoError(e))?,
            _ => todo!(),
        };
        Ok(Signer {
            derivation: self.derivation,
            current_keypair: self.next_keypair.clone(),
            next_keypair: new_next_keypair,
        })
    }
}
