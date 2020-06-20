use core::{fmt::Error, str::FromStr};
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
            _ => Err(Error),
        }
    }
}
