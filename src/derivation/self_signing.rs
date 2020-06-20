use crate::error::Error;
use core::str::FromStr;

#[derive(Copy, Clone)]
pub enum SelfSigningDerivations {
    Ed25519,
    ECDSAsecp256k1,
}

impl SelfSigningDerivations {
    pub fn to_str(&self) -> &str {
        match self {
            Self::Ed25519 => "0A",
            Self::ECDSAsecp256k1 => "0B",
        }
    }
}

impl FromStr for SelfSigningDerivations {
    type Err = Error;
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        match str {
            "0A" => Ok(Self::Ed25519),
            "0B" => Ok(Self::ECDSAsecp256k1),
            _ => Err(Error::DeserializationError(core::fmt::Error)),
        }
    }
}
