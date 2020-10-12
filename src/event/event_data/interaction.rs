use super::super::sections::DelegatingEventSeal;
use crate::error::Error;
use crate::prefix::SelfAddressingPrefix;
use crate::state::{EventSemantics, IdentifierState};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InteractionEvent {
    #[serde(rename = "prev")]
    pub previous_event_hash: SelfAddressingPrefix,

    pub data: Vec<DelegatingEventSeal>,
}

impl EventSemantics for InteractionEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        IdentifierState { ..state }
    }
}
