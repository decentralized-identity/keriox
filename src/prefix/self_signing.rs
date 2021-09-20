use super::Prefix;
use crate::{
    derivation::{self_signing::SelfSigning, DerivationCode},
    error::Error,
};
use base64::decode_config;
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, PartialEq, Clone, Hash)]
pub struct SelfSigningPrefix {
    pub derivation: SelfSigning,
    pub signature: Vec<u8>,
}

impl SelfSigningPrefix {
    pub fn new(code: SelfSigning, signature: Vec<u8>) -> Self {
        Self {
            derivation: code,
            signature,
        }
    }
}

impl FromStr for SelfSigningPrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = SelfSigning::from_str(s)?;

        if s.len() == code.prefix_b64_len() {
            Ok(Self::new(
                code,
                decode_config(&s[code.code_len()..code.prefix_b64_len()], base64::URL_SAFE)?,
            ))
        } else {
            Err(Error::SemanticError(format!(
                "Incorrect Prefix Length: {}",
                s
            )))
        }
    }
}

impl Prefix for SelfSigningPrefix {
    fn derivative(&self) -> Vec<u8> {
        self.signature.to_owned()
    }
    fn derivation_code(&self) -> String {
        self.derivation.to_str()
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
