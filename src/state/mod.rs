pub mod delegated;
pub mod signatory;

use crate::event::Event;
use crate::event_message::EventMessage;
use crate::prefix::Prefix;
use delegated::DelegatedIdentifierState;
use signatory::Signatory;
use ursa::CryptoError;

/// Identifier State
///
/// represents the accumulated state after applying events, based on section 13 of the paper
#[derive(Default, PartialEq)]
pub struct IdentifierState {
    pub prefix: Prefix,
    pub sn: u64,
    pub last: Prefix,
    pub current: Signatory,
    pub next: Signatory, // Prefix??
    pub delegated_keys: Vec<DelegatedIdentifierState>,
    pub tally: u64,
    pub witnesses: Vec<Prefix>,
}

impl IdentifierState {
    /// Verify
    ///
    /// ensures that the signatures of the event message are correct
    pub fn verify(&self, event_message: EventMessage) -> Result<Event, CryptoError> {
        todo!()
    }

    /// Apply
    ///
    /// validates and applies the semantic rules of the event to the event state
    fn apply(&self, event: Event) -> Result<Self, CryptoError> {
        todo!()
    }

    /// Verify and Apply
    ///
    /// Verifies the message and applies the event
    pub fn verify_and_apply(&self, event_message: EventMessage) -> Result<Self, CryptoError> {
        self.verify(event_message)
            .and_then(|event| self.apply(event))
    }
}
