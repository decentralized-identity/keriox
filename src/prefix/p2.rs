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

pub trait QualifiedCryptographicMaterial {
    fn derivative(&self) -> &[u8];

    fn derivation_code(&self) -> &str;

    fn to_str(&self) -> String {
        let encoded = encode_config(self.derivative(), base64::URL_SAFE);
        [
            self.derivation_code(),
            &encoded[..encoded.len() - self.derivation_code().len()],
        ]
        .join("")
    }
}

pub enum Prefix {
    PublicKey(PublicKeyPrefix),
    Signature(SignaturePrefix),
    Digest(DigestPrefix),
}

pub enum SignaturePrefix {
    Ed25519Sha512(Vec<u8>),
    ECDSAsecp256k1Sha256(Vec<u8>),
}

impl QualifiedCryptographicMaterial for Prefix {
    fn derivative(&self) -> &[u8] {
        match self {
            Self::PublicKey(pk) => pk.derivative(),
            Self::Signature(sig) => sig.derivative(),
            Self::Digest(dig) => dig.derivative(),
        }
    }

    fn derivation_code(&self) -> &str {
        match self {
            Self::PublicKey(pk) => pk.derivation_code(),
            Self::Signature(sig) => sig.derivation_code(),
            Self::Digest(dig) => dig.derivation_code(),
        }
    }
}

pub fn verify(
    data: &DigestPrefix,
    key: &PublicKeyPrefix,
    signature: &SignaturePrefix,
) -> Result<bool, Error> {
    match key {
        PublicKeyPrefix::Ed25519(pk) | PublicKeyPrefix::Ed25519NT(pk) => match signature {
            SignaturePrefix::Ed25519Sha512(sig) => {
                let ed = Ed25519Sha512::new();
                ed.verify(data.to_str().as_bytes(), sig, &pk)
                    .map_err(|e| Error::CryptoError(e))
            }
            _ => Err(Error::SemanticError("wrong sig type".to_string())),
        },
        PublicKeyPrefix::ECDSAsecp256k1(pk) | PublicKeyPrefix::ECDSAsecp256k1NT(pk) => {
            match signature {
                SignaturePrefix::ECDSAsecp256k1Sha256(sig) => {
                    let secp = EcdsaSecp256k1Sha256::new();
                    secp.verify(data.to_str().as_bytes(), sig, &pk)
                        .map_err(|e| Error::CryptoError(e))
                }
                _ => Err(Error::SemanticError("wrong sig type".to_string())),
            }
        }
        _ => Err(Error::SemanticError("inelligable key type".to_string())),
    }
}

impl QualifiedCryptographicMaterial for SignaturePrefix {
    fn derivative(&self) -> &[u8] {
        match self {
            Self::Ed25519Sha512(s) => &s,
            Self::ECDSAsecp256k1Sha256(s) => &s,
        }
    }

    fn derivation_code(&self) -> &str {
        match self {
            Self::Ed25519Sha512(_) => "0A",
            Self::ECDSAsecp256k1Sha256(_) => "0B",
        }
    }
}
