use super::DerivationCode;
use crate::{error::Error, prefix::BasicPrefix};
use core::str::FromStr;
use ursa::keys::PublicKey;

/// Basic Derivations
///
/// Basic prefix derivation is just a public key (2.3.1)
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Basic {
    ECDSAsecp256k1NT,
    ECDSAsecp256k1,
    Ed25519NT,
    Ed25519,
    Ed448NT,
    Ed448,
    X25519,
    X448,
}

impl Basic {
    pub fn derive(&self, public_key: PublicKey) -> BasicPrefix {
        BasicPrefix::new(*self, public_key)
    }
}

impl DerivationCode for Basic {
    fn to_str(&self) -> String {
        match self {
            Self::Ed25519NT => "B",
            Self::X25519 => "C",
            Self::Ed25519 => "D",
            Self::X448 => "L",
            Self::ECDSAsecp256k1NT => "1AAA",
            Self::ECDSAsecp256k1 => "1AAB",
            Self::Ed448NT => "1AAC",
            Self::Ed448 => "1AAD",
        }
        .into()
    }

    fn code_len(&self) -> usize {
        match self {
            Self::Ed25519NT | Self::Ed25519 | Self::X25519 | Self::X448 => 1,
            Self::ECDSAsecp256k1NT | Self::ECDSAsecp256k1 | Self::Ed448NT | Self::Ed448 => 4,
        }
    }

    fn derivative_b64_len(&self) -> usize {
        match self {
            Self::Ed25519NT | Self::Ed25519 | Self::X25519 => 43,
            Self::X448 => 75,
            Self::ECDSAsecp256k1NT | Self::ECDSAsecp256k1 => 47,
            Self::Ed448NT | Self::Ed448 => 76,
        }
    }
}

impl FromStr for Basic {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..1] {
            "B" => Ok(Self::Ed25519NT),
            "C" => Ok(Self::X25519),
            "D" => Ok(Self::Ed25519),
            "L" => Ok(Self::X448),
            "1" => match &s[1..4] {
                "AAA" => Ok(Self::ECDSAsecp256k1NT),
                "AAB" => Ok(Self::ECDSAsecp256k1),
                "AAC" => Ok(Self::Ed448NT),
                "AAD" => Ok(Self::Ed448),
                _ => Err(Error::DeserializationError),
            },
            _ => Err(Error::DeserializationError),
        }
    }
}
