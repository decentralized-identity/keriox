use super::super::sections::{KeyConfig, WitnessConfig};
use crate::{prefix::Prefix, state::EventSemantics};
use serde::{Deserialize, Serialize};

/// Rotation Event
///
/// Describtes the rotation (rot) event data
#[derive(Serialize, Deserialize, Debug)]
pub struct RotationEvent {
    #[serde(rename = "prev")]
    pub previous_event_hash: Prefix,

    #[serde(flatten)]
    pub key_config: KeyConfig,

    #[serde(flatten)]
    pub witness_config: WitnessConfig,
}

impl EventSemantics for RotationEvent {}
