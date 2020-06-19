pub mod delegated;
pub mod signatory;

use crate::error::Error;
use crate::event_message::EventMessage;
use crate::prefix::Prefix;
use delegated::DelegatedIdentifierState;
use signatory::Signatory;

/// Identifier State
///
/// represents the accumulated state after applying events, based on section 13 of the paper
#[derive(Default, PartialEq)]
pub struct IdentifierState {
    pub prefix: Prefix,
    pub sn: u64,
    pub last: Prefix,
    pub current: Signatory,
    pub next: Prefix,
    pub delegated_keys: Vec<DelegatedIdentifierState>,
    pub tally: u64,
    pub witnesses: Vec<Prefix>,
}

impl IdentifierState {
    /// Verify
    ///
    /// ensures that the signatures of the event message are correct
    pub fn verify<T: Verifiable>(&self, event_message: &T) -> Result<T, Error> {
        todo!()
    }

    /// Apply
    ///
    /// validates and applies the semantic rules of the event to the event state
    fn apply<T: EventSemantics>(self, event: &T) -> Result<Self, Error> {
        event.apply_to(self)
    }

    /// Verify and Apply
    ///
    /// Verifies the message and applies the event
    pub fn verify_and_apply<T: EventSemantics + Verifiable>(
        self,
        event_message: &T,
    ) -> Result<Self, Error> {
        let next = self.apply(event_message)?;
        next.verify(event_message)?;
        Ok(next)
    }
}

pub trait EventSemantics {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        Ok(state)
    }
}

pub trait Verifiable {
    fn verify_against(&self, state: &IdentifierState) -> Result<(), Error>;
}
