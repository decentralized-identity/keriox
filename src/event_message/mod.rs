use crate::error::Error;
use crate::event::Event;
use crate::prefix::Prefix;
use crate::state::Verifiable;
use crate::state::{EventSemantics, IdentifierState};
use crate::util::dfs_serializer::to_string;
use serde::{Deserialize, Serialize};

/// Versioned Event Message
///
/// A VersionedEventMessage represents any signed message involved in any version of the KERI protocol
#[derive(Serialize, Deserialize)]
#[serde(tag = "vs")]
pub enum VersionedEventMessage {
    #[serde(rename = "KERI_0.1")]
    V0_0(EventMessage),
}

/// Event Message
///
/// An EventMessage represents any signed message involved in the KERI protocol
#[derive(Serialize, Deserialize)]
pub struct EventMessage {
    #[serde(flatten)]
    pub event: Event,

    #[serde(rename = "sigs")]
    pub sig_config: Vec<usize>,

    /// Appended Signatures
    ///
    /// TODO in the recommended JSON encoding, the signatures are appended to the json body.
    #[serde(skip_serializing)]
    pub signatures: Vec<Prefix>,
}

impl EventSemantics for EventMessage {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        self.event.apply_to(state)
    }
}

impl EventSemantics for VersionedEventMessage {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        match self {
            Self::V0_0(e) => e.apply_to(state),
        }
    }
}

impl Verifiable for VersionedEventMessage {
    fn verify_against(&self, state: &IdentifierState) -> Result<bool, Error> {
        let serialized_data_extract = to_string(self);

        // extract relevant keys from state
        Ok(match self {
            Self::V0_0(e) => e
                .sig_config
                .iter()
                // get the signing keys indexed by event sig_config
                .map(|&index| &state.current.signers[index])
                // match them with the signatures
                .zip(&e.signatures)
                // check that each is valid
                .fold(true, |acc, (key, sig)| acc), // && key.verify(serialized_data_extract, sig)?)
        })
    }
}
