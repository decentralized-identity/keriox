use crate::{
    error::Error,
    prefix::{AttachedSignaturePrefix, BasicPrefix, Prefix, SelfAddressingPrefix},
};
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};
pub mod seal;

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct KeyConfig {
    #[serde(rename = "sith", with = "SerHex::<Compact>")]
    pub threshold: u64,

    #[serde(rename = "keys")]
    pub public_keys: Vec<BasicPrefix>,

    #[serde(rename = "nxt")]
    pub threshold_key_digest: SelfAddressingPrefix,
}

impl KeyConfig {
    pub fn new(
        public_keys: Vec<BasicPrefix>,
        threshold_key_digest: SelfAddressingPrefix,
        threshold: Option<u64>,
    ) -> Self {
        Self {
            threshold: threshold.map_or_else(|| public_keys.len() as u64 / 2 + 1, |t| t),
            public_keys,
            threshold_key_digest,
        }
    }

    /// Verify
    ///
    /// Verifies the given sigs against the given message using the KeyConfigs
    /// Public Keys, according to the indexes in the sigs.
    pub fn verify(&self, message: &[u8], sigs: &[AttachedSignaturePrefix]) -> Result<bool, Error> {
        // ensure there's enough sigs
        if sigs.len() as u64 >= self.threshold
            // and that there are not too many
            && sigs.len() <= self.public_keys.len()
            // and that there are no duplicates
            && sigs
                .iter()
                .fold(vec![0u64; self.public_keys.len()], |mut acc, sig| {
                    acc[sig.index as usize] += 1;
                    acc
                })
                .iter()
                .all(|n| *n <= 1)
        {
            Ok(sigs
                .iter()
                .fold(Ok(true), |acc: Result<bool, Error>, sig| {
                    Ok(acc?
                        && self
                            .public_keys
                            .get(sig.index as usize)
                            .ok_or(Error::SemanticError("Key index not present in set".into()))
                            .and_then(|key: &BasicPrefix| key.verify(message, &sig.signature))?)
                })?)
        } else {
            Err(Error::SemanticError("Invalid signatures set".into()))
        }
    }

    /// Verify Next
    ///
    /// Verifies that the given next KeyConfig matches that which is committed
    /// to in the threshold_key_digest of this KeyConfig
    pub fn verify_next(&self, next: &KeyConfig) -> bool {
        self.threshold_key_digest
            .verify_binding(&next.serialize_for_nxt())
    }

    /// Serialize For Next
    ///
    /// Serializes the KeyConfig for creation or verification of a threshold
    /// key digest commitment
    pub fn serialize_for_nxt(&self) -> Vec<u8> {
        serialize_for_commitment(self.threshold, &self.public_keys)
    }
}

/// Serialize For Commitment
///
/// Serializes a threshold and key set into the form
/// required for threshold key digest creation
pub fn serialize_for_commitment(threshold: u64, keys: &[BasicPrefix]) -> Vec<u8> {
    keys.iter()
        .fold(format!("{:x}", threshold).into(), |acc, pk| {
            [acc, pk.to_str().into()].concat()
        })
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct WitnessConfig {
    #[serde(rename = "toad", with = "SerHex::<Compact>")]
    pub tally: u64,

    #[serde(rename = "cuts")]
    pub prune: Vec<BasicPrefix>,

    #[serde(rename = "adds")]
    pub graft: Vec<BasicPrefix>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct InceptionWitnessConfig {
    #[serde(rename = "toad", with = "SerHex::<Compact>")]
    pub tally: u64,

    #[serde(rename = "wits")]
    pub initial_witnesses: Vec<BasicPrefix>,
}
