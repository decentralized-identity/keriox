pub mod delegated;
pub mod signatory;

use crate::error::Error;
use crate::prefix::{IdentifierPrefix, SelfAddressingPrefix};
use delegated::DelegatedIdentifierState;
use signatory::Signatory;

/// Identifier State
///
/// represents the accumulated state after applying events, based on section 13 of the paper
#[derive(Default, PartialEq, Debug)]
pub struct IdentifierState {
    pub prefix: IdentifierPrefix,
    pub sn: u64,
    pub last: SelfAddressingPrefix,
    pub current: Signatory,
    pub next: SelfAddressingPrefix,
    pub delegated_keys: Vec<DelegatedIdentifierState>,
    pub tally: u64,
    pub witnesses: Vec<IdentifierPrefix>,
}

impl IdentifierState {
    /// Verify
    ///
    /// ensures that the signatures of the event message are correct
    pub fn verify<T: Verifiable>(&self, message: &T) -> Result<bool, Error> {
        message.verify_against(self)
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
    /// NOTE that, for many events, the event must be applied semantically before the state is able
    /// to verify the message (e.g. rotation events), consuming the state.
    /// this could be optimised later perhaps.
    pub fn verify_and_apply<T: EventSemantics + Verifiable>(
        self,
        event_message: &T,
    ) -> Result<Self, Error> {
        let next = self.apply(event_message)?;
        if next.verify(event_message)? {
            Ok(next)
        } else {
            Err(Error::SemanticError("Verification Failure".to_string()))
        }
    }
}

/// EventSemantics
///
/// Describes an interface for applying the semantic rule of an event to the state of an Identifier
pub trait EventSemantics {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        // default impl is the identity transition
        Ok(state)
    }
}

/// Verifiable
///
/// Describes an interface for using an IdentifierState to verify a message
pub trait Verifiable {
    fn verify_against(&self, state: &IdentifierState) -> Result<bool, Error>;
}
