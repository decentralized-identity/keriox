use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    prefix::{AttachedSignaturePrefix, BasicPrefix, Prefix, SelfAddressingPrefix},
};
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};

pub mod key_config;
pub mod seal;

pub use key_config::KeyConfig;
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct WitnessConfig {
    #[serde(rename = "bt", with = "SerHex::<Compact>")]
    pub tally: u64,

    #[serde(rename = "br")]
    pub prune: Vec<BasicPrefix>,

    #[serde(rename = "ba")]
    pub graft: Vec<BasicPrefix>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct InceptionWitnessConfig {
    #[serde(rename = "bt", with = "SerHex::<Compact>")]
    pub tally: u64,

    #[serde(rename = "b")]
    pub initial_witnesses: Vec<BasicPrefix>,
}
