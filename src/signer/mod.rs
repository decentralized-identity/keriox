use crate::{error::Error, prefix::SeedPrefix};
use ursa::{
    keys::{PrivateKey, PublicKey},
    signatures::{ed25519, SignatureScheme},
};

pub trait KeyManager {
    fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, Error>;
    fn public_key(&self) -> PublicKey;
    fn next_public_key(&self) -> PublicKey;
    fn rotate(&mut self) -> Result<(), Error>;
}

pub struct CryptoBox {
    signer: Signer,
    next_priv_key: PrivateKey,
    pub next_pub_key: PublicKey,
    seeds: Vec<String>,
}

impl KeyManager for CryptoBox {
    fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, Error> {
        self.signer.sign(msg)
    }

    fn public_key(&self) -> PublicKey {
        self.signer.pub_key.clone()
    }

    fn next_public_key(&self) -> PublicKey {
        self.next_pub_key.clone()
    }

    fn rotate(&mut self) -> Result<(), Error> {
        let (next_pub_key, next_priv_key) =
            if let Some((next_secret, next_seeds)) = self.seeds.split_first() {
                let next_secret: SeedPrefix = next_secret.parse()?;
                self.seeds = next_seeds.to_vec();
                next_secret.derive_key_pair()?
            } else {
                let ed = ed25519::Ed25519Sha512::new();
                ed.keypair(None).map_err(|e| Error::CryptoError(e))?
            };

        let new_signer = Signer {
            priv_key: self.next_priv_key.clone(),
            pub_key: self.next_pub_key.clone(),
        };
        self.signer = new_signer;
        self.next_priv_key = next_priv_key;
        self.next_pub_key = next_pub_key;

        Ok(())
    }
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
            seeds: vec![],
        })
    }

    pub fn derive_from_seed(seeds: &[&str]) -> Result<Self, Error> {
        let (pub_key, priv_key) = match seeds.get(0) {
            Some(secret) => {
                let seed: SeedPrefix = secret.parse()?;
                seed.derive_key_pair()?
            }
            None => {
                let ed = ed25519::Ed25519Sha512::new();
                ed.keypair(None).map_err(|e| Error::CryptoError(e))?
            }
        };

        let (next_pub_key, next_priv_key) = match seeds.get(1) {
            Some(secret) => {
                let seed: SeedPrefix = secret.parse()?;
                seed.derive_key_pair()?
            }
            None => {
                let ed = ed25519::Ed25519Sha512::new();
                ed.keypair(None).map_err(|e| Error::CryptoError(e))?
            }
        };

        let seeds = seeds
            .get(2..)
            .unwrap_or(&vec![])
            .iter()
            .map(|s| s.to_string())
            .collect();

        Ok(CryptoBox {
            signer: Signer { pub_key, priv_key },
            next_pub_key,
            next_priv_key,
            seeds: seeds,
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
