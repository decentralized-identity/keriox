use super::super::sections::{seal::*, KeyConfig, WitnessConfig};
use crate::error::Error;
use crate::state::IdentifierState;
use crate::{prefix::SelfAddressingPrefix, state::signatory::Signatory, state::EventSemantics};
use serde::{Deserialize, Serialize};

/// Rotation Event
///
/// Describtes the rotation (rot) event data
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
            current: Signatory {
                threshold: self.key_config.threshold,
                signers: self.key_config.public_keys.clone(),
            },
            next: self.key_config.threshold_key_digest.clone(),
            tally: self.witness_config.tally,
            ..state
        })
    }
}
