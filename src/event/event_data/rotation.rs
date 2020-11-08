use super::super::sections::{seal::*, KeyConfig, WitnessConfig};
use crate::{
    error::Error,
    prefix::SelfAddressingPrefix,
    state::{EventSemantics, IdentifierState},
};
use serde::{Deserialize, Serialize};

/// Rotation Event
///
/// Describes the rotation (rot) event data
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RotationEvent {
    #[serde(rename = "dig")]
    pub previous_event_hash: SelfAddressingPrefix,

    #[serde(flatten)]
    pub key_config: KeyConfig,

    #[serde(flatten)]
    pub witness_config: WitnessConfig,

    pub data: Vec<Seal>,
}

impl EventSemantics for RotationEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        Ok(IdentifierState {
            current: self.key_config.clone(),
            tally: self.witness_config.tally,
            ..state
        })
    }
}
