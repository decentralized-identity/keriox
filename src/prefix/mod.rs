use crate::{
    derivation::{basic::Basic, self_signing::SelfSigning},
    error::Error,
};
use base64::encode_config;
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod attached_signature;
pub mod basic;
pub mod seed;
pub mod self_addressing;
pub mod self_signing;

pub use attached_signature::AttachedSignaturePrefix;
pub use basic::BasicPrefix;
pub use seed::SeedPrefix;
pub use self_addressing::SelfAddressingPrefix;
pub use self_signing::SelfSigningPrefix;

pub trait Prefix: FromStr<Err = Error> {
    fn derivative(&self) -> Vec<u8>;
    fn derivation_code(&self) -> String;
    fn to_str(&self) -> String {
        // empty data cannot be prefixed!
        match self.derivative().len() {
            0 => "".to_string(),
            _ => {
                let dc = self.derivation_code();
                let ec = encode_config(self.derivative(), base64::URL_SAFE_NO_PAD);
                [dc, ec].join("")
            }
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
    fn derivative(&self) -> Vec<u8> {
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
            SelfSigning::Ed25519Sha512 => Ok(key
                .public_key
                .verify_ed(data.as_ref(), &signature.signature)),
            _ => Err(Error::SemanticError("wrong sig type".to_string())),
        },
        Basic::ECDSAsecp256k1 | Basic::ECDSAsecp256k1NT => match signature.derivation {
            SelfSigning::ECDSAsecp256k1Sha256 => Ok(key
                .public_key
                .verify_ecdsa(data.as_ref(), &signature.signature)),
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
    use crate::{
        derivation::self_addressing::SelfAddressing,
        keys::{PrivateKey, PublicKey},
    };
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;

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
        let pref = Basic::Ed25519NT.derive(PublicKey::new(
            ed25519_dalek::PublicKey::from_bytes(&[0; 32])?
                .to_bytes()
                .to_vec(),
        ));

        assert_eq!(
            pref.to_str(),
            "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );

        Ok(())
    }

    #[test]
    fn verify() -> Result<(), Error> {
        let data_string = "hello there";

        let kp = Keypair::generate(&mut OsRng);
        let pub_key = PublicKey::new(kp.public.to_bytes().to_vec());
        let priv_key = PrivateKey::new(kp.secret.to_bytes().to_vec());

        let key_prefix = Basic::Ed25519NT.derive(pub_key);

        let sig = priv_key.sign_ed(&data_string.as_bytes())?;
        let sig_prefix = SelfSigningPrefix {
            derivation: SelfSigning::Ed25519Sha512,
            signature: sig,
        };

        let check = key_prefix.verify(&data_string.as_bytes(), &sig_prefix);
        assert!(check.is_ok());
        assert!(check.unwrap());

        Ok(())
    }

    #[test]
    fn prefix_deserialization() -> Result<(), Error> {
        /// Helper function that checks whether all codes fulfill the condition
        /// given by predicate `pred`.
        fn all_codes<F>(codes: Vec<(&str, usize)>, pred: F) -> Result<(), Error>
        where
            F: Fn(IdentifierPrefix) -> bool,
        {
            for (code, length) in codes {
                let pref: IdentifierPrefix =
                    [code.to_string(), "A".repeat(length)].join("").parse()?;
                assert!(pred(pref.clone()));
                assert_eq!(pref.derivation_code(), code);
            }
            Ok(())
        }

        // All codes that are mapped to `BasicPrefix`.
        let basic_codes = vec!["B", "C", "D", "L", "1AAA", "1AAB", "1AAC", "1AAD"].into_iter();
        // Allowed string lengths for respective basic codes.
        let allowed_lengths = vec![43, 43, 43, 75, 47, 47, 76, 76].into_iter();
        let is_basic = |identifier| matches!(&identifier, IdentifierPrefix::Basic(_));
        all_codes(basic_codes.zip(allowed_lengths).collect(), is_basic)?;

        // All codes that are mapped to `SelfAddressingPrefix`.
        let self_adressing_codes =
            vec!["E", "F", "G", "H", "I", "0D", "0E", "0F", "0G"].into_iter();
        // Allowed string lengths for respective self addressing codes.
        let allowed_lengths = vec![43, 43, 43, 43, 43, 86, 86, 86, 86].into_iter();
        let is_self_addresing =
            |identifier| matches!(&identifier, IdentifierPrefix::SelfAddressing(_));
        all_codes(
            self_adressing_codes.zip(allowed_lengths).collect(),
            is_self_addresing,
        )?;

        // All codes that are mapped to `SelfSigningPrefix`.
        let is_self_signing = |identifier| matches!(&identifier, IdentifierPrefix::SelfSigning(_));
        // Allowed string lengths for respective self signing codes.
        let self_signing_codes = vec!["0B", "0C", "1AAE"].into_iter();
        let allowed_lengths = vec![86, 86, 152].into_iter();
        all_codes(
            self_signing_codes.zip(allowed_lengths).collect(),
            is_self_signing,
        )?;

        Ok(())
    }

    #[test]
    fn prefix_serialization() -> Result<(), Error> {
        // The lengths of respective vectors are choosen according to [0, Section 14.2]
        // [0]: https://github.com/SmithSamuelM/Papers/raw/master/whitepapers/KERI_WP_2.x.web.pdf

        // Test BasicPrefix serialization.
        assert_eq!(
            BasicPrefix::new(
                Basic::Ed25519NT,
                PublicKey::new(
                    ed25519_dalek::PublicKey::from_bytes(&[0; 32])?
                        .to_bytes()
                        .to_vec()
                )
            )
            .to_str(),
            ["B".to_string(), "A".repeat(43)].join("")
        );
        assert_eq!(
            BasicPrefix::new(
                Basic::X25519,
                PublicKey::new(
                    ed25519_dalek::PublicKey::from_bytes(&[0; 32])?
                        .to_bytes()
                        .to_vec()
                )
            )
            .to_str(),
            ["C".to_string(), "A".repeat(43)].join("")
        );
        assert_eq!(
            BasicPrefix::new(
                Basic::Ed25519,
                PublicKey::new(
                    ed25519_dalek::PublicKey::from_bytes(&[0; 32])?
                        .to_bytes()
                        .to_vec()
                )
            )
            .to_str(),
            ["D".to_string(), "A".repeat(43)].join("")
        );
        assert_eq!(
            BasicPrefix::new(Basic::X448, PublicKey::new([0; 56].to_vec())).to_str(),
            ["L".to_string(), "A".repeat(75)].join("")
        );
        assert_eq!(
            BasicPrefix::new(Basic::ECDSAsecp256k1NT, PublicKey::new([0; 33].to_vec())).to_str(),
            ["1AAA".to_string(), "A".repeat(44)].join("")
        );
        assert_eq!(
            BasicPrefix::new(Basic::ECDSAsecp256k1, PublicKey::new([0; 33].to_vec())).to_str(),
            ["1AAB".to_string(), "A".repeat(44)].join("")
        );
        assert_eq!(
            BasicPrefix::new(Basic::Ed448NT, PublicKey::new([0; 57].to_vec())).to_str(),
            ["1AAC".to_string(), "A".repeat(76)].join("")
        );
        assert_eq!(
            BasicPrefix::new(Basic::Ed448, PublicKey::new([0; 57].to_vec())).to_str(),
            ["1AAD".to_string(), "A".repeat(76)].join("")
        );

        // Test SelfAddressingPrefix serialization.
        assert_eq!(
            SelfAddressingPrefix::new(SelfAddressing::Blake3_256, vec![0; 32]).to_str(),
            ["E".to_string(), "A".repeat(43)].join("")
        );
        assert_eq!(
            SelfAddressingPrefix::new(SelfAddressing::Blake2B256(vec!()), vec![0; 32]).to_str(),
            ["F".to_string(), "A".repeat(43)].join("")
        );
        assert_eq!(
            SelfAddressingPrefix::new(SelfAddressing::Blake2S256(vec!()), vec![0; 32]).to_str(),
            ["G".to_string(), "A".repeat(43)].join("")
        );
        assert_eq!(
            SelfAddressingPrefix::new(SelfAddressing::SHA3_256, vec![0; 32]).to_str(),
            ["H".to_string(), "A".repeat(43)].join("")
        );
        assert_eq!(
            SelfAddressingPrefix::new(SelfAddressing::SHA2_256, vec![0; 32]).to_str(),
            ["I".to_string(), "A".repeat(43)].join("")
        );
        assert_eq!(
            SelfAddressingPrefix::new(SelfAddressing::Blake3_512, vec![0; 64]).to_str(),
            ["0D".to_string(), "A".repeat(86)].join("")
        );
        assert_eq!(
            SelfAddressingPrefix::new(SelfAddressing::SHA3_512, vec![0; 64]).to_str(),
            ["0E".to_string(), "A".repeat(86)].join("")
        );
        assert_eq!(
            SelfAddressingPrefix::new(SelfAddressing::Blake2B512, vec![0; 64]).to_str(),
            ["0F".to_string(), "A".repeat(86)].join("")
        );
        assert_eq!(
            SelfAddressingPrefix::new(SelfAddressing::SHA2_512, vec![0; 64]).to_str(),
            ["0G".to_string(), "A".repeat(86)].join("")
        );

        // Test SelfSigningPrefix serialization.
        assert_eq!(
            SelfSigningPrefix::new(SelfSigning::ECDSAsecp256k1Sha256, vec![0; 64]).to_str(),
            ["0C".to_string(), "A".repeat(86)].join("")
        );
        assert_eq!(
            SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, vec![0; 64]).to_str(),
            ["0B".to_string(), "A".repeat(86)].join("")
        );
        assert_eq!(
            SelfSigningPrefix::new(SelfSigning::Ed448, vec![0; 114]).to_str(),
            ["1AAE".to_string(), "A".repeat(152)].join("")
        );

        Ok(())
    }
}
