use super::super::sections::seal::*;
use crate::error::Error;
use crate::prefix::SelfAddressingPrefix;
use crate::state::{EventSemantics, IdentifierState};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct InteractionEvent {
    #[serde(rename = "p")]
    pub previous_event_hash: SelfAddressingPrefix,

    #[serde(rename = "a")]
    pub data: Vec<Seal>,
}

impl EventSemantics for InteractionEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        Ok(IdentifierState { ..state })
    }
}
