use super::{Prefix, SelfSigningPrefix};
use crate::{
    derivation::{
        attached_signature_code::AttachedSignatureCode, self_signing::SelfSigning, DerivationCode,
    },
    error::Error,
};
use base64::decode_config;
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, PartialEq, Clone)]
pub struct AttachedSignaturePrefix {
    pub index: u16,
    pub signature: SelfSigningPrefix,
}

impl AttachedSignaturePrefix {
    pub fn new(code: SelfSigning, signature: Vec<u8>, index: u16) -> Self {
        Self {
            signature: SelfSigningPrefix::new(code, signature),
            index,
        }
    }
}

impl FromStr for AttachedSignaturePrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = AttachedSignatureCode::from_str(s)?;

        if (s.len()) == code.prefix_b64_len() {
            Ok(Self::new(
                code.code,
                decode_config(&s[code.code_len()..code.prefix_b64_len()], base64::URL_SAFE)?,
                code.index,
            ))
        } else {
            Err(Error::SemanticError(format!(
                "Incorrect Prefix Length: {}",
                s
            )))
        }
    }
}

impl Prefix for AttachedSignaturePrefix {
    fn derivative(&self) -> Vec<u8> {
        self.signature.signature.to_vec()
    }
    fn derivation_code(&self) -> String {
        AttachedSignatureCode::new(self.signature.derivation, self.index).to_str()
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
    use crate::derivation::self_signing::SelfSigning;

    #[test]
    fn deserialize() -> Result<(), Error> {
        let attached_ed_1 = "ABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let attached_secp_2 = "BCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let attached_448_3 = "0AADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        let pref_ed_1 = AttachedSignaturePrefix::from_str(attached_ed_1)?;
        let pref_secp_2 = AttachedSignaturePrefix::from_str(attached_secp_2)?;
        let pref_448_3 = AttachedSignaturePrefix::from_str(attached_448_3)?;

        assert_eq!(1, pref_ed_1.index);
        assert_eq!(2, pref_secp_2.index);
        assert_eq!(3, pref_448_3.index);

        assert_eq!(SelfSigning::Ed25519Sha512, pref_ed_1.signature.derivation);
        assert_eq!(
            SelfSigning::ECDSAsecp256k1Sha256,
            pref_secp_2.signature.derivation
        );
        assert_eq!(SelfSigning::Ed448, pref_448_3.signature.derivation);
        Ok(())
    }

    #[test]
    fn serialize() -> Result<(), Error> {
        let pref_ed_2 = AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, vec![0u8; 64], 2);
        let pref_secp_6 =
            AttachedSignaturePrefix::new(SelfSigning::ECDSAsecp256k1Sha256, vec![0u8; 64], 6);
        let pref_448_4 = AttachedSignaturePrefix::new(SelfSigning::Ed448, vec![0u8; 114], 4);

        assert_eq!(88, pref_ed_2.to_str().len());
        assert_eq!(88, pref_secp_6.to_str().len());
        assert_eq!(156, pref_448_4.to_str().len());

        assert_eq!("ACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", pref_ed_2.to_str());
        assert_eq!("BGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", pref_secp_6.to_str());
        assert_eq!("0AAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", pref_448_4.to_str());
        Ok(())
    }
}
