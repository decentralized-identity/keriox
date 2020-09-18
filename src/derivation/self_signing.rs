use super::DerivationCode;
use crate::error::Error;
use core::str::FromStr;

/// Self Signing Derivations
///
/// A self signing prefix derivation outputs a signature as its derivative (2.3.5)
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SelfSigning {
    Ed25519Sha512,
    ECDSAsecp256k1Sha256,
    Ed448,
}

impl DerivationCode for SelfSigning {
    fn to_str(&self) -> String {
        match self {
            Self::Ed25519Sha512 => "0B",
            Self::ECDSAsecp256k1Sha256 => "0C",
            Self::Ed448 => "1AAE",
        }
        .into()
    }

    fn code_len(&self) -> usize {
        match self {
            Self::Ed25519Sha512 | Self::ECDSAsecp256k1Sha256 => 2,
            Self::Ed448 => 4,
        }
    }

    fn derivative_b64_len(&self) -> usize {
        match self {
            Self::Ed25519Sha512 | Self::ECDSAsecp256k1Sha256 => 86,
            Self::Ed448 => 152,
        }
    }
}

impl FromStr for SelfSigning {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..1] {
            "0" => match &s[1..2] {
                "B" => Ok(Self::Ed25519Sha512),
                "C" => Ok(Self::ECDSAsecp256k1Sha256),
                _ => Err(Error::DeserializationError),
            },
            "1" => match &s[1..4] {
                "AAE" => Ok(Self::Ed448),
                _ => Err(Error::DeserializationError),
            },
            _ => Err(Error::DeserializationError),
        }
    }
}
