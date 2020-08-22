use super::Prefix;
use crate::error::Error;
use base64::decode_config;
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, PartialEq, Clone)]
pub enum SelfSigningPrefix {
    ECDSAsecp256k1Sha256(Vec<u8>),
    Ed25519Sha512(Vec<u8>),
    Ed448(Vec<u8>),
}

impl FromStr for SelfSigningPrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[1..2] {
            "B" => Ok(Self::ECDSAsecp256k1Sha256(decode_config(
                &s[2..],
                base64::URL_SAFE,
            )?)),
            "C" => Ok(Self::Ed25519Sha512(decode_config(
                &s[2..],
                base64::URL_SAFE,
            )?)),
            "A" => match &s[2..4] {
                "AE" => Ok(Self::Ed448(decode_config(&s[4..], base64::URL_SAFE)?)),
                _ => Err(Error::DeserializationError),
            },
            _ => Err(Error::DeserializationError),
        }
    }
}

impl Prefix for SelfSigningPrefix {
    fn derivative(&self) -> &[u8] {
        match self {
            Self::ECDSAsecp256k1Sha256(sig) => &sig,
            Self::Ed25519Sha512(sig) => &sig,
            Self::Ed448(sig) => &sig,
        }
    }
    fn derivation_code(&self) -> String {
        match self {
            Self::ECDSAsecp256k1Sha256(_) => "0B".to_string(),
            Self::Ed25519Sha512(_) => "0C".to_string(),
            Self::Ed448(_) => "1AAE".to_string(),
        }
    }
}

/// Serde compatible Serialize
impl Serialize for SelfSigningPrefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deserialize
impl<'de> Deserialize<'de> for SelfSigningPrefix {
    fn deserialize<D>(deserializer: D) -> Result<SelfSigningPrefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        SelfSigningPrefix::from_str(&s).map_err(serde::de::Error::custom)
    }
}
