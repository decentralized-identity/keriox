use crate::event::Event;
use crate::prefix::Prefix;
use serde::{Deserialize, Serialize};

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
