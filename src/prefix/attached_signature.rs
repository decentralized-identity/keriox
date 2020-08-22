use super::{self_signing::SelfSigningPrefix, Prefix};
use crate::error::Error;
use base64::{decode_config, display::Base64Display};
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, PartialEq, Clone)]
pub struct AttachedSignaturePrefix {
    pub index: u8,
    pub sig: SelfSigningPrefix,
}

impl FromStr for AttachedSignaturePrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            index: decode_config(&s[..1], base64::URL_SAFE_NO_PAD)?[0],
            sig: SelfSigningPrefix::from_str(&s[1..])?,
        })
    }
}

impl Prefix for AttachedSignaturePrefix {
    fn derivative(&self) -> &[u8] {
        &self.sig.derivative()
    }
    fn derivation_code(&self) -> String {
        format!(
            "{}{}",
            Base64Display::with_config(&[self.index], base64::URL_SAFE_NO_PAD),
            match self.sig {
                SelfSigningPrefix::Ed25519Sha512(_) => "B",
                SelfSigningPrefix::ECDSAsecp256k1Sha256(_) => "C",
                SelfSigningPrefix::Ed448(_) => "AAE",
            },
        )
    }
}

/// Serde compatible Serialize
impl Serialize for AttachedSignaturePrefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deserialize
impl<'de> Deserialize<'de> for AttachedSignaturePrefix {
    fn deserialize<D>(deserializer: D) -> Result<AttachedSignaturePrefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        AttachedSignaturePrefix::from_str(&s).map_err(serde::de::Error::custom)
    }
}
