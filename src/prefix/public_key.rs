use super::p2::{verify, QualifiedCryptographicMaterial};
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

pub enum PublicKeyPrefix {
    Ed25519NT(PublicKey),
    X25519(PublicKey),
    Ed25519(PublicKey),
    ECDSAsecp256k1NT(PublicKey),
    ECDSAsecp256k1(PublicKey),
}

impl QualifiedCryptographicMaterial for PublicKeyPrefix {
    fn derivative(&self) -> &[u8] {
        match self {
            Self::Ed25519NT(p) => &p.0,
            Self::X25519(p) => &p.0,
            Self::Ed25519(p) => &p.0,
            Self::ECDSAsecp256k1NT(p) => &p.0,
            Self::ECDSAsecp256k1(p) => &p.0,
        }
    }

    fn derivation_code(&self) -> &str {
        match self {
            Self::Ed25519NT(_) => "A",
            Self::X25519(_) => "B",
            Self::Ed25519(_) => "C",
            Self::ECDSAsecp256k1NT(_) => "G",
            Self::ECDSAsecp256k1(_) => "H",
        }
    }
}

impl PublicKeyPrefix {
    pub fn public_key(&self) -> &PublicKey {
        match self {
            Self::Ed25519NT(p) => &p,
            Self::X25519(p) => &p,
            Self::Ed25519(p) => &p,
            Self::ECDSAsecp256k1NT(p) => &p,
            Self::ECDSAsecp256k1(p) => &p,
        }
    }

    pub fn verify(&self, data: &DigestPrefix, signature: &SignaturePrefix) -> Result<bool, Error> {
        verify(data, self, signature)
    }
}
