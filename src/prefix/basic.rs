use super::{verify, Prefix, SelfSigningPrefix};
use crate::{
    derivation::{basic::Basic, DerivationCode},
    error::Error,
};
use base64::decode_config;
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ursa::keys::PublicKey;

#[derive(Debug, PartialEq, Clone)]
pub struct BasicPrefix {
    pub derivation: Basic,
    pub public_key: PublicKey,
}

impl BasicPrefix {
    pub fn new(code: Basic, public_key: PublicKey) -> Self {
        Self {
            derivation: code,
            public_key,
        }
    }

    pub fn verify(&self, data: &[u8], signature: &SelfSigningPrefix) -> Result<bool, Error> {
        verify(data, self, signature)
    }
}

impl FromStr for BasicPrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = Basic::from_str(s)?;

        if s.len() == code.prefix_b64_len() {
            Ok(Self::new(
                code,
                PublicKey(decode_config(
                    &s[code.code_len()..code.prefix_b64_len()],
                    base64::URL_SAFE,
                )?),
            ))
        } else {
            Err(Error::SemanticError(format!(
                "Incorrect Prefix Length: {}",
                s
            )))
        }
    }
}

impl Prefix for BasicPrefix {
    fn derivative(&self) -> &[u8] {
        &self.public_key.0
    }
    fn derivation_code(&self) -> String {
        self.derivation.to_str()
    }
}

/// Serde compatible Serialize
impl Serialize for BasicPrefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deserialize
impl<'de> Deserialize<'de> for BasicPrefix {
    fn deserialize<D>(deserializer: D) -> Result<BasicPrefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        BasicPrefix::from_str(&s).map_err(serde::de::Error::custom)
    }
}
