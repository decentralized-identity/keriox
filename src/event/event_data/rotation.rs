use super::super::sections::{KeyConfig, WitnessConfig};
use super::EventSemantics;
use serde::{Deserialize, Serialize};

/// Rotation Event
///
/// Describtes the rotation (rot) event data
#[derive(Serialize, Deserialize, Debug)]
pub struct RotationEvent {
    #[serde(flatten)]
    pub key_config: KeyConfig,

    #[serde(flatten)]
    pub witness_config: WitnessConfig,
}

impl EventSemantics for RotationEvent {}
