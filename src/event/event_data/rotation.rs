use super::super::sections::{seal::*, KeyConfig, WitnessConfig};
use crate::{error::Error, prefix::{BasicPrefix, SelfAddressingPrefix}, state::{EventSemantics, IdentifierState}};
use serde::{Deserialize, Serialize};

/// Rotation Event
///
/// Describes the rotation (rot) event data
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RotationEvent {
    #[serde(rename = "p")]
    pub previous_event_hash: SelfAddressingPrefix,

    #[serde(flatten)]
    pub key_config: KeyConfig,

    #[serde(flatten)]
    pub witness_config: WitnessConfig,

    #[serde(rename = "a")]
    pub data: Vec<Seal>,
}

impl EventSemantics for RotationEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        if state.current.verify_next(&self.key_config) {
            // witness rotation processing
            let witnesses = if self.witness_config.prune.len() > 0
                || self.witness_config.graft.len() > 0 {
                   let mut prunned = state.witnesses
                        .into_iter()
                        .filter(|e| !self.witness_config.prune.contains(e))
                        .collect::<Vec<BasicPrefix>>();
                    prunned
                        .append(&mut self.witness_config.graft.clone());
                    prunned
                } else { state.witnesses.clone() };
            Ok(IdentifierState {
                current: self.key_config.clone(),
                tally: self.witness_config.tally,
                witnesses,
                ..state
            })
        } else {
            Err(Error::SemanticError("Incorrect Key Config binding".into()))
        }
    }
}
