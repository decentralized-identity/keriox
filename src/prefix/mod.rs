use crate::{
    derivation::{basic::Basic, self_signing::SelfSigning},
    error::Error,
};
use base64::encode_config;
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ursa::signatures::prelude::*;

pub mod attached_signature;
pub mod basic;
pub mod parse;
pub mod seed;
pub mod self_addressing;
pub mod self_signing;

pub use attached_signature::AttachedSignaturePrefix;
pub use basic::BasicPrefix;
pub use seed::SeedPrefix;
pub use self_addressing::SelfAddressingPrefix;
pub use self_signing::SelfSigningPrefix;

pub trait Prefix: FromStr<Err = Error> {
    fn derivative(&self) -> &[u8];
    fn derivation_code(&self) -> String;
    fn to_str(&self) -> String {
        // empty data cannot be prefixed!
        match self.derivative().len() {
            0 => "".to_string(),
            _ => [
                self.derivation_code(),
                encode_config(self.derivative(), base64::URL_SAFE_NO_PAD),
            ]
            .join(""),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum IdentifierPrefix {
    Basic(BasicPrefix),
    SelfAddressing(SelfAddressingPrefix),
    SelfSigning(SelfSigningPrefix),
}

impl FromStr for IdentifierPrefix {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match BasicPrefix::from_str(s) {
            Ok(bp) => Ok(Self::Basic(bp)),
            Err(_) => match SelfAddressingPrefix::from_str(s) {
                Ok(sa) => Ok(Self::SelfAddressing(sa)),
                Err(_) => Ok(Self::SelfSigning(SelfSigningPrefix::from_str(s)?)),
            },
        }
    }
}

impl Prefix for IdentifierPrefix {
    fn derivative(&self) -> &[u8] {
        match self {
            Self::Basic(bp) => bp.derivative(),
            Self::SelfAddressing(sap) => sap.derivative(),
            Self::SelfSigning(ssp) => ssp.derivative(),
        }
    }
    fn derivation_code(&self) -> String {
        match self {
            Self::Basic(bp) => bp.derivation_code(),
            Self::SelfAddressing(sap) => sap.derivation_code(),
            Self::SelfSigning(ssp) => ssp.derivation_code(),
        }
    }
}

/// Serde compatible Serialize
impl Serialize for IdentifierPrefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deserialize
impl<'de> Deserialize<'de> for IdentifierPrefix {
    fn deserialize<D>(deserializer: D) -> Result<IdentifierPrefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        IdentifierPrefix::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Default for IdentifierPrefix {
    fn default() -> Self {
        IdentifierPrefix::SelfAddressing(SelfAddressingPrefix::default())
    }
}

/// Verify
///
/// Uses a public key to verify a signature against some data, with
/// the key and signature represented by Basic and Self-Signing Prefixes
pub fn verify(
    data: &[u8],
    key: &BasicPrefix,
    signature: &SelfSigningPrefix,
) -> Result<bool, Error> {
    match key.derivation {
        Basic::Ed25519 | Basic::Ed25519NT => match signature.derivation {
            SelfSigning::Ed25519Sha512 => {
                let ed = Ed25519Sha512::new();
                ed.verify(data.as_ref(), &signature.signature, &key.public_key)
                    .map_err(|e| Error::CryptoError(e))
            }
            _ => Err(Error::SemanticError("wrong sig type".to_string())),
        },
        Basic::ECDSAsecp256k1 | Basic::ECDSAsecp256k1NT => match signature.derivation {
            SelfSigning::ECDSAsecp256k1Sha256 => {
                let secp = EcdsaSecp256k1Sha256::new();
                secp.verify(data.as_ref(), &signature.signature, &key.public_key)
                    .map_err(|e| Error::CryptoError(e))
            }
            _ => Err(Error::SemanticError("wrong sig type".to_string())),
        },
        _ => Err(Error::SemanticError("inelligable key type".to_string())),
    }
}

/// Derive
///
/// Derives the Basic Prefix corrosponding to the given Seed Prefix
pub fn derive(seed: &SeedPrefix, transferable: bool) -> Result<BasicPrefix, Error> {
    let (pk, _) = seed.derive_key_pair()?;
    Ok(BasicPrefix::new(
        match seed {
            SeedPrefix::RandomSeed256Ed25519(_) if transferable => Basic::Ed25519,
            SeedPrefix::RandomSeed256Ed25519(_) if !transferable => Basic::Ed25519NT,
            SeedPrefix::RandomSeed256ECDSAsecp256k1(_) if transferable => Basic::ECDSAsecp256k1,
            SeedPrefix::RandomSeed256ECDSAsecp256k1(_) if !transferable => Basic::ECDSAsecp256k1NT,
            _ => return Err(Error::ImproperPrefixType),
        },
        pk,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ursa::{keys, signatures};

    #[test]
    fn simple_deserialize() -> Result<(), Error> {
        let pref: IdentifierPrefix = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse()?;

        assert_eq!(pref.derivation_code(), "B");

        assert_eq!(pref.derivative().len(), 32);

        assert_eq!(pref.derivative().to_vec(), vec![0u8; 32]);

        Ok(())
    }

    #[test]
    fn length() -> Result<(), Error> {
        // correct
        assert!(IdentifierPrefix::from_str("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_ok());
        assert!(IdentifierPrefix::from_str("CBBBBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_ok());

        // too short
        assert!(!IdentifierPrefix::from_str("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_ok());

        // too long
        assert!(
            !IdentifierPrefix::from_str("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_ok()
        );

        // not a real prefix
        assert!(
            !IdentifierPrefix::from_str("ZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_ok()
        );

        // not base 64 URL
        assert!(
            !IdentifierPrefix::from_str("BAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAA").is_ok()
        );

        Ok(())
    }

    #[test]
    fn simple_serialize() -> Result<(), Error> {
        let pref = Basic::Ed25519NT.derive(keys::PublicKey(vec![0; 32]));

        assert_eq!(
            pref.to_str(),
            "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );

        Ok(())
    }

    #[test]
    fn verify() -> Result<(), Error> {
        let data_string = "hello there";

        let ed = signatures::ed25519::Ed25519Sha512::new();

        let (pub_key, priv_key) = ed
            .keypair(Some(keys::KeyGenOption::UseSeed(vec![0u8; 32])))
            .map_err(|e| Error::CryptoError(e))?;

        let key_prefix = Basic::Ed25519NT.derive(pub_key);

        let sig = ed
            .sign(&data_string.as_bytes(), &priv_key)
            .map_err(|e| Error::CryptoError(e))?;

        let sig_prefix = SelfSigningPrefix {
            derivation: SelfSigning::Ed25519Sha512,
            signature: sig,
        };

        assert!(
            true,
            key_prefix.verify(&data_string.as_bytes(), &sig_prefix)?
        );

        Ok(())
    }
}
