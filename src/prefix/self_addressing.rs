use super::Prefix;
use crate::derivation::*;
use crate::error::Error;
use base64::decode_config;
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, PartialEq, Clone)]
pub enum SelfAddressingPrefix {
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

impl SelfAddressingPrefix {
    pub fn verify_binding(&self, sed: &[u8]) -> bool {
        match self {
            Self::Blake3_256(d) => &blake3_256_digest(sed) == d,
            Self::Blake2B256(d) => &blake2b_256_digest(sed) == d,
            Self::Blake2S256(d) => &blake2s_256_digest(sed) == d,
            Self::SHA3_256(d) => &sha3_256_digest(sed) == d,
            Self::SHA2_256(d) => &sha2_256_digest(sed) == d,
            Self::Blake3_512(d) => &blake3_512_digest(sed) == d,
            Self::SHA3_512(d) => &sha3_512_digest(sed) == d,
            Self::Blake2B512(d) => &blake2b_512_digest(sed) == d,
            Self::SHA2_512(d) => &sha2_512_digest(sed) == d,
        }
    }
}

impl FromStr for SelfAddressingPrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..1] {
            "E" => Ok(Self::Blake3_256(decode_config(&s[1..], base64::URL_SAFE)?)),
            "F" => Ok(Self::Blake2B256(decode_config(&s[1..], base64::URL_SAFE)?)),
            "G" => Ok(Self::Blake2S256(decode_config(&s[1..], base64::URL_SAFE)?)),
            "H" => Ok(Self::SHA3_256(decode_config(&s[1..], base64::URL_SAFE)?)),
            "I" => Ok(Self::SHA3_256(decode_config(&s[1..], base64::URL_SAFE)?)),
            "0" => match &s[1..2] {
                "D" => Ok(Self::Blake3_512(decode_config(&s[2..], base64::URL_SAFE)?)),
                "E" => Ok(Self::SHA3_512(decode_config(&s[2..], base64::URL_SAFE)?)),
                "F" => Ok(Self::Blake2B512(decode_config(&s[2..], base64::URL_SAFE)?)),
                "G" => Ok(Self::SHA2_512(decode_config(&s[2..], base64::URL_SAFE)?)),
                _ => Err(Error::DeserializationError),
            },
            _ => Err(Error::DeserializationError),
        }
    }
}

impl Prefix for SelfAddressingPrefix {
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
    fn derivation_code(&self) -> String {
        match self {
            Self::Blake3_256(_) => "E".to_string(),
            Self::Blake2B256(_) => "F".to_string(),
            Self::Blake2S256(_) => "G".to_string(),
            Self::SHA3_256(_) => "H".to_string(),
            Self::SHA2_256(_) => "I".to_string(),
            Self::Blake3_512(_) => "0D".to_string(),
            Self::SHA3_512(_) => "0E".to_string(),
            Self::Blake2B512(_) => "0F".to_string(),
            Self::SHA2_512(_) => "0G".to_string(),
        }
    }
}

/// Serde compatible Serialize
impl Serialize for SelfAddressingPrefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deserialize
impl<'de> Deserialize<'de> for SelfAddressingPrefix {
    fn deserialize<D>(deserializer: D) -> Result<SelfAddressingPrefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        SelfAddressingPrefix::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Default for SelfAddressingPrefix {
    fn default() -> Self {
        SelfAddressingPrefix::Blake3_256(vec![])
    }
}
