use crate::event::Event;
use crate::prefix::Prefix;
use serde::{Deserialize, Serialize};

/// Event Message
///
/// An EventMessage represents any signed message involved in the KERI protocol
/// All types share mandatory prefix, sn, sig config and signatures fields, but differ
/// in the event data they carry
#[derive(Serialize, Deserialize)]
pub struct EventMessage {
    #[serde(flatten)]
    pub event: Event,

    #[serde(rename(serialize = "sigs", deserialize = "sigs"))]
    pub sig_config: Vec<u64>,

    /// Appended Signatures
    ///
    /// TODO in the recommended JSON encoding, the signatures are appended to the json body.
    /// how do you do that in serde?
    pub signatures: Vec<Prefix>,
}
