use crate::prefix::{BasicPrefix, IdentifierPrefix, SelfAddressingPrefix};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyConfig {
    #[serde(rename = "sith")]
    pub threshold: usize,

    #[serde(rename = "keys")]
    pub public_keys: Vec<BasicPrefix>,

    #[serde(rename = "next")]
    pub threshold_key_digest: SelfAddressingPrefix,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WitnessConfig {
    #[serde(rename = "toad")]
    pub tally: usize,

    #[serde(rename = "adds")]
    pub graft: Vec<IdentifierPrefix>,

    #[serde(rename = "cuts")]
    pub prune: Vec<IdentifierPrefix>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InceptionWitnessConfig {
    #[serde(rename = "toad")]
    pub tally: usize,

    #[serde(rename = "wits")]
    pub initial_witnesses: Vec<IdentifierPrefix>,
}
