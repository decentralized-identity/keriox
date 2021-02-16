use crate::{error::Error, prefix::SeedPrefix};
use ursa::{
    keys::{PrivateKey, PublicKey},
    signatures::{ed25519, SignatureScheme},
};

pub struct CryptoBox {
    signer: Signer,
    next_priv_key: PrivateKey,
    pub next_pub_key: PublicKey,
}

impl CryptoBox {
    pub fn new() -> Result<Self, Error> {
        let ed = ed25519::Ed25519Sha512::new();
        let signer = Signer::new()?;
        let (next_pub_key, next_priv_key) = ed.keypair(None).map_err(|e| Error::CryptoError(e))?;
        Ok(CryptoBox {
            signer,
            next_pub_key,
            next_priv_key,
        })
    }

    pub fn derive_from_seed(current_secret: &str, next_secret: &str) -> Result<Self, Error> {
        let current_secret: SeedPrefix = current_secret.parse()?;
        let (pub_key, priv_key) = current_secret.derive_key_pair()?;
        let next_secret: SeedPrefix = next_secret.parse()?;
        let (next_pub_key, next_priv_key) = next_secret.derive_key_pair()?;
        Ok(CryptoBox {
            signer: Signer { pub_key, priv_key },
            next_pub_key,
            next_priv_key,
        })
    }

    pub fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, Error> {
        self.signer.sign(msg)
    }

    pub fn public_key(&self) -> PublicKey {
        self.signer.pub_key.clone()
    }

    pub fn rotate(&self) -> Result<Self, Error> {
        let ed = ed25519::Ed25519Sha512::new();
        let (next_pub_key, next_priv_key) = ed.keypair(None).map_err(|e| Error::CryptoError(e))?;
        let new_signer = Signer {
            priv_key: self.next_priv_key.clone(),
            pub_key: self.next_pub_key.clone(),
        };

        Ok(CryptoBox {
            signer: new_signer,
            next_priv_key,
            next_pub_key,
        })
    }
}

struct Signer {
    priv_key: PrivateKey,
    pub pub_key: PublicKey,
}

impl Signer {
    pub fn new() -> Result<Self, Error> {
        let ed = ed25519::Ed25519Sha512::new();
        let (pub_key, priv_key) = ed.keypair(None).map_err(|e| Error::CryptoError(e))?;

        Ok(Signer { pub_key, priv_key })
    }

    pub fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, Error> {
        let signature = ed25519::Ed25519Sha512::new()
            .sign(&msg, &self.priv_key)
            .map_err(|e| Error::CryptoError(e))?;
        Ok(signature)
    }
}
