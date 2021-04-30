use std::rc::Rc;
use crate::{error::Error, keys::{KeriPublicKey, KeriSignerKey, pk_into_vk, vk_into_pk}, prefix::SeedPrefix};
use ed25519_dalek::{PublicKey, SecretKey, Keypair};
use k256::elliptic_curve::rand_core::OsRng;

pub trait KeyManager {
    fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, Error>;
    fn public_key(&self) -> Rc<dyn KeriPublicKey>;
    fn next_public_key(&self) -> Rc<dyn KeriPublicKey>;
    fn rotate(&mut self) -> Result<(), Error>;
}

pub struct CryptoBox {
    signer: Signer,
    next_priv_key: Rc<dyn KeriSignerKey>,
    pub next_pub_key: Rc<dyn KeriPublicKey>,
    seeds: Vec<String>,
}

impl KeyManager for CryptoBox {
    fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, Error> {
        self.signer.sign(msg)
    }

    fn public_key(&self) -> Rc<dyn KeriPublicKey> {
        Rc::clone(&self.signer.pub_key)
    }

    fn next_public_key(&self) -> Rc<dyn KeriPublicKey> {
        Rc::clone(&self.next_pub_key)
    }

    fn rotate(&mut self) -> Result<(), Error> {
        let (next_pub_key, next_priv_key) =
            if let Some((next_secret, next_seeds)) = self.seeds.split_first() {
                let next_secret: SeedPrefix = next_secret.parse()?;
                self.seeds = next_seeds.to_vec();
                next_secret.derive_key_pair()?
            } else {
                let kp = Keypair::generate(&mut OsRng{});
                let vk: Rc<dyn KeriPublicKey> = Rc::new(kp.public);
                let sk: Rc<dyn KeriSignerKey> = Rc::new(kp.secret);
                (pk_into_vk(vk), sk)
            };

        let new_signer = Signer {
            priv_key: Rc::clone(&self.next_priv_key),
            pub_key: Rc::clone(&self.next_pub_key),
        };
        self.signer = new_signer;
        self.next_priv_key = next_priv_key;
        self.next_pub_key = vk_into_pk(next_pub_key);

        Ok(())
    }
}
//#[cfg(feature = "demo")]
impl CryptoBox {
    pub fn new() -> Result<Self, Error> {
        let signer = Signer::new()?;
        let kp = Keypair::generate(&mut OsRng{});
        let (next_pub_key, next_priv_key) = (kp.public, kp.secret);
        Ok(CryptoBox {
            signer,
            next_pub_key: Rc::new(next_pub_key),
            next_priv_key: Rc::new(next_priv_key),
            seeds: vec![],
        })
    }

    pub fn derive_from_seed(seeds: &[&str]) -> Result<Self, Error> {
        let (pub_key, priv_key) = match seeds.get(0) {
            Some(secret) => {
                let secret = SecretKey::from_bytes(secret.as_bytes())
                    .map_err(|_| Error::SemanticError("failed to convert provided seet to SecretKey".into()))?;
                let public = PublicKey::from(&secret);
                (public, secret)
            }
            None => {
               ed_new_public_private()
            }
        };

        let (next_pub_key, next_priv_key) = match seeds.get(1) {
            Some(secret) => {
                let seed: SeedPrefix = secret.parse()?;
                seed.derive_key_pair()?
            }
            None => {
                let (vk, sk) = ed_new_public_private();
                let vk: Rc<dyn KeriPublicKey> = Rc::new(vk);
                let sk: Rc<dyn KeriSignerKey> = Rc::new(sk);
                (pk_into_vk(vk), sk)
            }
        };

        let seeds = seeds
            .get(2..)
            .unwrap_or(&vec![])
            .iter()
            .map(|s| s.to_string())
            .collect();

        Ok(CryptoBox {
            signer: Signer { pub_key: Rc::new(pub_key), priv_key: Rc::new(priv_key) },
            next_pub_key: vk_into_pk(next_pub_key),
            next_priv_key,
            seeds,
        })
    }
}

struct Signer {
    priv_key: Rc<dyn KeriSignerKey>,
    pub pub_key: Rc<dyn KeriPublicKey>,
}

impl Signer {
    pub fn new() -> Result<Self, Error> {
        let ed = Keypair::generate(&mut OsRng);
        let pub_key: Rc<dyn KeriPublicKey> = Rc::new(ed.public);
        let priv_key: Rc<dyn KeriSignerKey> = Rc::new(ed.secret);

        Ok(Signer { pub_key, priv_key })
    }

    pub fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, Error> {
        self.priv_key.sign(msg)
    }
}

fn ed_new_public_private() -> (PublicKey, SecretKey) {
    let kp = Keypair::generate(&mut OsRng{});
    (kp.public, kp.secret)
}

