use super::Prefix;
use crate::error::Error;
use base64::decode_config;
use core::str::FromStr;
use ursa::{keys::*, signatures::prelude::*};

#[derive(Debug, PartialEq, Clone)]
pub enum SeedPrefix {
    RandomSeed128(Vec<u8>),
    RandomSeed256Ed25519(Vec<u8>),
    RandomSeed256ECDSAsecp256k1(Vec<u8>),
    RandomSeed448(Vec<u8>),
}

impl SeedPrefix {
    pub fn derive_key_pair(&self) -> Result<(PublicKey, PrivateKey), Error> {
        match self {
            Self::RandomSeed256Ed25519(seed) => {
                Ed25519Sha512::expand_keypair(&seed.clone()).map_err(|e| Error::CryptoError(e))
            }
            Self::RandomSeed256ECDSAsecp256k1(seed) => EcdsaSecp256k1Sha256::new()
                .keypair(Some(KeyGenOption::UseSeed(seed.clone())))
                .map_err(|e| Error::CryptoError(e)),
            _ => Err(Error::ImproperPrefixType),
        }
    }
}

impl FromStr for SeedPrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..1] {
            "A" => Ok(Self::RandomSeed256Ed25519(decode_config(
                &s[1..],
                base64::URL_SAFE,
            )?)),
            "J" => Ok(Self::RandomSeed256ECDSAsecp256k1(decode_config(
                &s[1..],
                base64::URL_SAFE,
            )?)),
            "K" => Ok(Self::RandomSeed448(decode_config(
                &s[1..],
                base64::URL_SAFE,
            )?)),
            "0" => match &s[1..2] {
                "A" => Ok(Self::RandomSeed128(decode_config(
                    &s[2..],
                    base64::URL_SAFE,
                )?)),
                _ => Err(Error::DeserializationError),
            },
            _ => Err(Error::DeserializationError),
        }
    }
}

impl Prefix for SeedPrefix {
    fn derivative(&self) -> &[u8] {
        match self {
            Self::RandomSeed256Ed25519(seed) => &seed,
            Self::RandomSeed256ECDSAsecp256k1(seed) => &seed,
            Self::RandomSeed448(seed) => &seed,
            Self::RandomSeed128(seed) => &seed,
        }
    }
    fn derivation_code(&self) -> String {
        match self {
            Self::RandomSeed256Ed25519(_) => "A".to_string(),
            Self::RandomSeed256ECDSAsecp256k1(_) => "J".to_string(),
            Self::RandomSeed448(_) => "K".to_string(),
            Self::RandomSeed128(_) => "0A".to_string(),
        }
    }
}
