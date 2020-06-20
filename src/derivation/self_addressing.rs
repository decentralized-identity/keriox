use core::{fmt::Error, str::FromStr};

pub enum SelfAddressingDerivations {
    // length 1 derivations
    Blake3_256,
    Blake2B256,
    Blake2S256,
    SHA3_256,
    SHA2_256,

    // length 2 derivations
    Blake3_512,
    SHA3_512,
    Blake2B512,
    SHA2_512,
}

impl SelfAddressingDerivations {
    pub fn to_str(&self) -> &str {
        match self {
            Self::Blake3_256 => "D",
            Self::Blake2B256 => "E",
            Self::Blake2S256 => "F",
            Self::SHA3_256 => "I",
            Self::SHA2_256 => "J",
            Self::Blake3_512 => "0C",
            Self::SHA3_512 => "0D",
            Self::Blake2B512 => "0E",
            Self::SHA2_512 => "0F",
        }
    }
}

impl FromStr for SelfAddressingDerivations {
    type Err = Error;
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        match str {
            "D" => Ok(Self::Blake3_256),
            "E" => Ok(Self::Blake2B256),
            "F" => Ok(Self::Blake2S256),
            "I" => Ok(Self::SHA3_256),
            "J" => Ok(Self::SHA2_256),
            "0C" => Ok(Self::Blake3_512),
            "0D" => Ok(Self::SHA3_512),
            "0E" => Ok(Self::Blake2B512),
            "0F" => Ok(Self::SHA2_512),
            _ => Err(Error),
        }
    }
}
