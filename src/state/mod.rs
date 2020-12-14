use crate::{
    error::Error,
    event::sections::KeyConfig,
    prefix::{BasicPrefix, IdentifierPrefix},
};
use serde::{Deserialize, Serialize};

/// Identifier State
///
/// represents the accumulated state after applying events, based on section 13 of the paper
#[derive(Default, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct IdentifierState {
    pub prefix: IdentifierPrefix,
    pub sn: u64,
    #[serde(skip)]
    pub last: Vec<u8>,
    pub current: KeyConfig,
    pub delegated_keys: Vec<IdentifierPrefix>,
    pub tally: u64,
    pub witnesses: Vec<BasicPrefix>,
    pub delegator: Option<IdentifierPrefix>,
}

impl IdentifierState {
    /// Apply
    ///
    /// validates and applies the semantic rules of the event to the event state
    pub fn apply<T: EventSemantics>(self, event: &T) -> Result<Self, Error> {
        event.apply_to(self)
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
