use crate::prefix::{BasicPrefix, IdentifierPrefix, SelfAddressingPrefix};
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};
pub mod seal;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyConfig {
    #[serde(rename = "sith", with = "SerHex::<Compact>")]
    pub threshold: u64,

    #[serde(rename = "keys")]
    pub public_keys: Vec<BasicPrefix>,

    #[serde(rename = "nxt")]
    pub threshold_key_digest: SelfAddressingPrefix,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct WitnessConfig {
    #[serde(rename = "toad", with = "SerHex::<Compact>")]
    pub tally: u64,

    #[serde(rename = "cuts")]
    pub prune: Vec<IdentifierPrefix>,

    #[serde(rename = "adds")]
    pub graft: Vec<IdentifierPrefix>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct InceptionWitnessConfig {
    #[serde(rename = "toad", with = "SerHex::<Compact>")]
    pub tally: u64,

    #[serde(rename = "wits")]
    pub initial_witnesses: Vec<IdentifierPrefix>,
}
