use crate::event::{event_data::EventSemantics, Event};
use crate::prefix::Prefix;
use crate::state::IdentifierState;
use serde::{Deserialize, Serialize};

/// Versioned Event Message
///
/// A VersionedEventMessage represents any signed message involved in any version of the KERI protocol
#[derive(Serialize, Deserialize)]
#[serde(tag = "vs")]
pub enum VersionedEventMessage {
    V0(EventMessage),
}

/// Event Message
///
/// An EventMessage represents any signed message involved in the KERI protocol
#[derive(Serialize, Deserialize)]
pub struct EventMessage {
    #[serde(flatten)]
    pub event: Event,

    #[serde(rename(serialize = "sigs", deserialize = "sigs"))]
    pub sig_config: Vec<u64>,

    /// Appended Signatures
    ///
    /// TODO in the recommended JSON encoding, the signatures are appended to the json body.
    #[serde(skip_serializing)]
    pub signatures: Vec<Prefix>,
}

impl EventSemantics for EventMessage {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, &str> {
        self.event.apply_to(state)
    }
}

impl EventSemantics for VersionedEventMessage {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, &str> {
        match self {
            Self::V0(e) => e.apply_to(state),
        }
    }
}
