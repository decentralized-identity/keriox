use crate::error::Error;
use base64::{decode_config, encode_config};
use core::{
    fmt::{Display, Formatter},
    str::FromStr,
};
use ursa::{
    keys::PublicKey,
    signatures::{ed25519::Ed25519Sha512, secp256k1::EcdsaSecp256k1Sha256, SignatureScheme},
};

use super::p2::QualifiedCryptographicMaterial;

pub enum DigestPrefix {
    Blake3_256(Vec<u8>),
    Blake2B256(Vec<u8>),
    Blake2S256(Vec<u8>),
    SHA3_256(Vec<u8>),
    SHA2_256(Vec<u8>),
    Blake3_512(Vec<u8>),
    SHA3_512(Vec<u8>),
    Blake2B512(Vec<u8>),
    SHA2_512(Vec<u8>),
}

impl QualifiedCryptographicMaterial for DigestPrefix {
    fn derivative(&self) -> &[u8] {
        match self {
            Self::Blake3_256(d) => &d,
            Self::Blake2B256(d) => &d,
            Self::Blake2S256(d) => &d,
            Self::SHA3_256(d) => &d,
            Self::SHA2_256(d) => &d,
            Self::Blake3_512(d) => &d,
            Self::SHA3_512(d) => &d,
            Self::Blake2B512(d) => &d,
            Self::SHA2_512(d) => &d,
        }
    }
    fn derivation_code(&self) -> &str {
        match self {
            Self::Blake3_256(_) => "D",
            Self::Blake2B256(_) => "E",
            Self::Blake2S256(_) => "F",
            Self::SHA3_256(_) => "I",
            Self::SHA2_256(_) => "J",
            Self::Blake3_512(_) => "0C",
            Self::SHA3_512(_) => "0D",
            Self::Blake2B512(_) => "0E",
            Self::SHA2_512(_) => "0F",
        }
    }
}
