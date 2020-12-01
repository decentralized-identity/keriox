use crate::prefix::BasicPrefix;
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};

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
