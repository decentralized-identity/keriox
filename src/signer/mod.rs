use crate::{error::Error, keys::Key, prefix::SeedPrefix};
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use rand::rngs::OsRng;
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
    seeds: Box<dyn Iterator<Item = SeedPrefix>>,
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
        let (next_pub_key, next_priv_key) = {
            let nxt_key_seed = self.seeds.next();
            derive_key_pair(nxt_key_seed)?
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
        let signer = Signer::new();
        let (next_pub_key, next_priv_key) = derive_key_pair(None)?;
        Ok(CryptoBox {
            signer,
            next_pub_key,
            next_priv_key,
            seeds: Box::new(std::iter::empty()),
        })
    }

    pub fn derive_from_seed(seeds: Vec<SeedPrefix>) -> Result<Self, Error> {
        let mut seeds = seeds.into_iter();
        let (pub_key, priv_key) = derive_key_pair(seeds.next())?;

        let (next_pub_key, next_priv_key) = derive_key_pair(seeds.next())?;

        Ok(CryptoBox {
            signer: Signer { pub_key, priv_key },
            next_pub_key,
            next_priv_key,
            seeds: Box::new(seeds),
        })
    }
}

struct Signer {
    priv_key: Key,
    pub pub_key: Key,
}

impl Signer {
    pub fn new() -> Self {
        let (pk, sk) = ed_new_public_private();
        let pub_key = Key::new(pk.to_bytes().to_vec());
        let priv_key = Key::new(sk.to_bytes().to_vec());

        Signer { pub_key, priv_key }
    }

    pub fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, Error> {
        self.priv_key.sign_ed(msg)
    }
}

fn ed_new_public_private() -> (PublicKey, SecretKey) {
    let kp = Keypair::generate(&mut OsRng {});
    (kp.public, kp.secret)
}

fn derive_key_pair(seed: Option<SeedPrefix>) -> Result<(Key, Key), Error> {
    match seed {
        Some(secret) => secret.derive_key_pair(),
        None => {
            let (vk, sk) = ed_new_public_private();
            let vk = Key::new(vk.to_bytes().to_vec());
            let sk = Key::new(sk.to_bytes().to_vec());
            Ok((vk, sk))
        }
    }
}

#[test]
fn test_derive_keypairs_from_seed() -> Result<(), Error> {
    use base64;
    // taken from KERIPY: tests/core/test_eventing.py#1512
    let seeds = vec![
        "ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc",
        "A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q",
        "AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y",
        "Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8",
    ];

    let expected_pubkeys = vec![
        "SuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA=",
        "VcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI=",
        "T1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8=",
        "KPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ=",
    ];

    let mut cryptobox =
        CryptoBox::derive_from_seed(seeds.iter().map(|seed| seed.parse().unwrap()).collect())?;
    assert_eq!(
        base64::encode_config(cryptobox.public_key().key(), base64::URL_SAFE),
        expected_pubkeys[0]
    );
    assert_eq!(
        base64::encode_config(cryptobox.next_public_key().key(), base64::URL_SAFE),
        expected_pubkeys[1]
    );

    cryptobox.rotate()?;
    assert_eq!(
        base64::encode_config(cryptobox.public_key().key(), base64::URL_SAFE),
        expected_pubkeys[1]
    );
    assert_eq!(
        base64::encode_config(cryptobox.next_public_key().key(), base64::URL_SAFE),
        expected_pubkeys[2]
    );

    cryptobox.rotate()?;
    assert_eq!(
        base64::encode_config(cryptobox.public_key().key(), base64::URL_SAFE),
        expected_pubkeys[2]
    );
    assert_eq!(
        base64::encode_config(cryptobox.next_public_key().key(), base64::URL_SAFE),
        expected_pubkeys[3]
    );

    Ok(())
}
