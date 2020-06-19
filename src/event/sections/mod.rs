use crate::prefix::Prefix;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyConfig {
    #[serde(rename(serialize = "sith", deserialize = "sith"))]
    pub threshold: u64,

    #[serde(rename(serialize = "keys", deserialize = "keys"))]
    pub public_keys: Vec<Prefix>,

    #[serde(rename(serialize = "next", deserialize = "next"))]
    pub threshold_key_digest: Prefix,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WitnessConfig {
    #[serde(rename(serialize = "toad", deserialize = "toad"))]
    pub tally: u64,

    #[serde(rename(serialize = "adds", deserialize = "adds"))]
    pub graft: Vec<Prefix>,

    #[serde(rename(serialize = "cuts", deserialize = "cuts"))]
    pub prune: Vec<Prefix>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InceptionWitnessConfig {
    #[serde(rename = "toad")]
    pub tally: u64,

    #[serde(rename = "wits")]
    pub initial_witnesses: Vec<Prefix>,
}
