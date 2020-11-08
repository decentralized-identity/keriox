use super::super::sections::{InceptionWitnessConfig, KeyConfig};
use crate::{
    error::Error,
    state::{EventSemantics, IdentifierState},
};
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
            current: self.key_config.clone(),
            witnesses: self.witness_config.initial_witnesses.clone(),
            tally: self.witness_config.tally,
            ..state
        })
    }
}
