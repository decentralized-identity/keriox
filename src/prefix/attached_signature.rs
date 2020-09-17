use super::Prefix;
use crate::{
    derivation::{attached_signature_code::AttachedSignatureCode, DerivationCode},
    error::Error,
};
use base64::decode_config;
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, PartialEq, Clone)]
pub struct AttachedSignaturePrefix {
    pub code: AttachedSignatureCode,
    pub signature: Vec<u8>,
}

impl AttachedSignaturePrefix {
    pub fn new(code: AttachedSignatureCode, signature: Vec<u8>) -> Self {
        Self { code, signature }
    }
}

impl FromStr for AttachedSignaturePrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = AttachedSignatureCode::from_str(s)?;

        if (s.len()) == code.prefix_b64_len() {
            Ok(Self::new(
                code,
                decode_config(&s[code.code_len()..code.prefix_b64_len()], base64::URL_SAFE)?,
            ))
        } else {
            Err(Error::SemanticError("Incorrect Prefix Length".into()))
        }
    }
}

impl Prefix for AttachedSignaturePrefix {
    fn derivative(&self) -> &[u8] {
        &self.signature
    }
    fn derivation_code(&self) -> String {
        self.code.to_str()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivation::{
        attached_signature_code::AttachedSignatureCode, self_signing::SelfSigning,
    };

    #[test]
    fn deserialize() -> Result<(), Error> {
        let attached_ed_1 = "AB";
        let attached_secp_2 = "BC";
        let attached_448_3 = "0AAD";

        let pref_ed_1 = AttachedSignaturePrefix::from_str(attached_ed_1)?;
        let pref_secp_2 = AttachedSignaturePrefix::from_str(attached_secp_2)?;
        let pref_448_3 = AttachedSignaturePrefix::from_str(attached_448_3)?;

        assert_eq!(1, pref_ed_1.code.index);
        assert_eq!(2, pref_secp_2.code.index);
        assert_eq!(3, pref_448_3.code.index);

        assert_eq!(SelfSigning::Ed25519Sha512, pref_ed_1.code.code);
        assert_eq!(SelfSigning::ECDSAsecp256k1Sha256, pref_secp_2.code.code);
        assert_eq!(SelfSigning::Ed448, pref_448_3.code.code);
        Ok(())
    }

    #[test]
    fn serialize() -> Result<(), Error> {
        let pref_ed_2 = AttachedSignaturePrefix::new(
            AttachedSignatureCode::new(SelfSigning::Ed25519Sha512, 2),
            vec![0u8; 64],
        );
        let pref_secp_6 = AttachedSignaturePrefix::new(
            AttachedSignatureCode::new(SelfSigning::ECDSAsecp256k1Sha256, 6),
            vec![0u8; 64],
        );
        let pref_448_4 = AttachedSignaturePrefix::new(
            AttachedSignatureCode::new(SelfSigning::Ed448, 4),
            vec![0u8; 114],
        );

        assert_eq!(88, pref_ed_2.to_str().len());
        assert_eq!(88, pref_secp_6.to_str().len());
        assert_eq!(156, pref_448_4.to_str().len());

        assert_eq!("ACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", pref_ed_2.to_str());
        assert_eq!("BGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", pref_secp_6.to_str());
        assert_eq!("0AAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", pref_448_4.to_str());
        Ok(())
    }
}
