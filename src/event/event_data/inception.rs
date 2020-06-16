use super::super::sections::{KeyConfig, WitnessConfig};
use super::EventSemantics;
use serde::{Deserialize, Serialize};

/// Inception Event
///
/// Describes the inception (icp) event data,
#[derive(Serialize, Deserialize, Debug)]
pub struct InceptionEvent {
    #[serde(flatten)]
    pub key_config: KeyConfig,

    #[serde(flatten)]
    pub witness_config: WitnessConfig,
}

impl EventSemantics for InceptionEvent {}
