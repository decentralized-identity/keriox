use std::ops::{Deref, DerefMut};
use crate::{error::Error, keys::Key, prefix::SeedPrefix};
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use rand::rngs::OsRng;

#[cfg(feature = "wallet")]
pub mod wallet;

pub trait KeyManager {
    fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, Error>;
    fn public_key(&self) -> Key;
    fn next_public_key(&self) -> Key;
    fn rotate(&mut self) -> Result<(), Error>;
}

pub struct CryptoBox {
    signer: Signer,
    next_priv_key: Key,
    pub next_pub_key: Key,
    seeds: Vec<String>,
}

impl DerefMut for CryptoBox {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self
    }
}

impl Deref for CryptoBox {
    type Target = CryptoBox;

    fn deref(&self) -> &Self::Target {
        self
    }
}

impl KeyManager for CryptoBox {
    fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, Error> {
        self.signer.sign(msg)
    }

    fn public_key(&self) -> Key {
        self.signer.pub_key.clone()
    }

    fn next_public_key(&self) -> Key {
        self.next_pub_key.clone()
    }

    fn rotate(&mut self) -> Result<(), Error> {
        let (next_pub_key, next_priv_key) =
            if let Some((next_secret, next_seeds)) = self.seeds.split_first() {
                let next_secret: SeedPrefix = next_secret.parse()?;
                self.seeds = next_seeds.to_vec();
                next_secret.derive_key_pair()?
            } else {
                let kp = Keypair::generate(&mut OsRng {});
                let vk = Key::new(kp.public.as_bytes().to_vec());
                let sk = Key::new(kp.secret.as_bytes().to_vec());
                (vk, sk)
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
//#[cfg(feature = "demo")]
impl CryptoBox {
    pub fn new() -> Result<Self, Error> {
        let signer = Signer::new()?;
        let kp = Keypair::generate(&mut OsRng {});
        let (next_pub_key, next_priv_key) = (
            Key::new(kp.public.as_bytes().to_vec()),
            Key::new(kp.secret.as_bytes().to_vec()),
        );
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
                let secret = SecretKey::from_bytes(secret.as_bytes()).map_err(|_| {
                    Error::SemanticError("failed to convert provided seet to SecretKey".into())
                })?;
                let public = PublicKey::from(&secret);
                (public, secret)
            }
            None => ed_new_public_private(),
        };

        let (next_pub_key, next_priv_key) = match seeds.get(1) {
            Some(secret) => {
                let seed: SeedPrefix = secret.parse()?;
                seed.derive_key_pair()?
            }
            None => {
                let (vk, sk) = ed_new_public_private();
                let vk = Key::new(vk.to_bytes().to_vec());
                let sk = Key::new(sk.to_bytes().to_vec());
                (vk, sk)
            }
        };

        let seeds = seeds
            .get(2..)
            .unwrap_or(&vec![])
            .iter()
            .map(|s| s.to_string())
            .collect();

        Ok(CryptoBox {
            signer: Signer {
                pub_key: Key::new(pub_key.to_bytes().to_vec()),
                priv_key: Key::new(priv_key.to_bytes().to_vec()),
            },
            next_pub_key,
            next_priv_key,
            seeds,
        })
    }
}

struct Signer {
    priv_key: Key,
    pub pub_key: Key,
}

impl Signer {
    pub fn new() -> Result<Self, Error> {
        let ed = Keypair::generate(&mut OsRng);
        let pub_key = Key::new(ed.public.to_bytes().to_vec());
        let priv_key = Key::new(ed.secret.to_bytes().to_vec());

        Ok(Signer { pub_key, priv_key })
    }

    pub fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, Error> {
        self.priv_key.sign_ed(msg)
    }
}

fn ed_new_public_private() -> (PublicKey, SecretKey) {
    let kp = Keypair::generate(&mut OsRng {});
    (kp.public, kp.secret)
}
