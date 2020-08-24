use super::super::sections::{InceptionWitnessConfig, KeyConfig};
use crate::error::Error;
use crate::state::signatory::Signatory;
use crate::state::EventSemantics;
use crate::state::IdentifierState;
use serde::{Deserialize, Serialize};

/// Inception Event
///
/// Describes the inception (icp) event data,
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InceptionEvent {
    #[serde(flatten)]
    pub key_config: KeyConfig,

    #[serde(flatten)]
    pub witness_config: InceptionWitnessConfig,

    #[serde(rename = "cnfg")]
    pub inception_configuration: Vec<String>,
}

impl EventSemantics for InceptionEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        Ok(IdentifierState {
            current: Signatory {
                threshold: self.key_config.threshold,
                signers: self.key_config.public_keys.clone(),
            },
            next: self.key_config.threshold_key_digest.clone(),
            witnesses: self.witness_config.initial_witnesses.clone(),
            tally: self.witness_config.tally,
            ..state
        })
    }
}
