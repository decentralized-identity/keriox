use crate::prefix::Prefix;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyConfig {
    #[serde(rename = "sith")]
    pub threshold: u64,

    #[serde(rename = "keys")]
    pub public_keys: Vec<Prefix>,

    #[serde(rename = "next")]
    pub threshold_key_digest: Prefix,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WitnessConfig {
    #[serde(rename = "toad")]
    pub tally: u64,

    #[serde(rename = "adds")]
    pub graft: Vec<Prefix>,

    #[serde(rename = "cuts")]
    pub prune: Vec<Prefix>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InceptionWitnessConfig {
    #[serde(rename = "toad")]
    pub tally: u64,

    #[serde(rename = "wits")]
    pub initial_witnesses: Vec<Prefix>,
}
