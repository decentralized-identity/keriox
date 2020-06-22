use crate::{derivation::SignatureSchemes, error::Error};
use core::str::FromStr;
use ursa::signatures::{ed25519::Ed25519Sha512, secp256k1::EcdsaSecp256k1Sha256, SignatureScheme};

#[derive(Copy, Clone)]
pub enum PublicKeyDerivations {
    Ed25519NT,
    X25519,
    Ed25519,
    ECDSAsecp256k1NT,
    ECDSAsecp256k1,
}

impl PublicKeyDerivations {
    pub fn to_str(&self) -> &str {
        match self {
            Self::Ed25519NT => "A",
            Self::X25519 => "B",
            Self::Ed25519 => "C",
            Self::ECDSAsecp256k1NT => "G",
            Self::ECDSAsecp256k1 => "H",
        }
    }

    // TODO this is efficient enough for Ed25519 but not for ECDSAsecp256k1
    pub fn to_scheme(&self) -> SignatureSchemes {
        match self {
            Self::Ed25519NT | Self::Ed25519 | Self::X25519 => {
                SignatureSchemes::Ed25519Sha512(Ed25519Sha512::new())
            }
            Self::ECDSAsecp256k1 | Self::ECDSAsecp256k1NT => {
                SignatureSchemes::ECDSAsecp256k1Sha256(EcdsaSecp256k1Sha256::new())
            }
        }
    }
}

impl FromStr for PublicKeyDerivations {
    type Err = Error;
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        match str {
            "A" => Ok(Self::Ed25519NT),
            "B" => Ok(Self::X25519),
            "C" => Ok(Self::Ed25519),
            "G" => Ok(Self::ECDSAsecp256k1NT),
            "H" => Ok(Self::ECDSAsecp256k1),
            _ => Err(Error::DeserializationError(core::fmt::Error)),
        }
    }
}
