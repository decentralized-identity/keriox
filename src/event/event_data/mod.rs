pub mod delegated;
pub mod inception;
pub mod interaction;
pub mod receipt;
pub mod rotation;

use crate::{
    error::Error,
    state::{EventSemantics, IdentifierState},
};
use serde::{Deserialize, Serialize};

pub use self::{
    delegated::DelegatedInceptionEvent,
    inception::InceptionEvent,
    interaction::InteractionEvent,
    receipt::Receipt,
    rotation::RotationEvent,
};

/// Event Data
///
/// Event Data conveys the semantic content of a KERI event.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged, rename_all = "lowercase")]
pub enum EventData {
    Icp(InceptionEvent),
    Rot(RotationEvent),
    Ixn(InteractionEvent),
    Dip(DelegatedInceptionEvent),
    Drt(RotationEvent),
    Rct(Receipt),
}

impl EventSemantics for EventData {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        match self {
            Self::Icp(e) => e.apply_to(state),
            Self::Rot(e) => e.apply_to(state),
            Self::Ixn(e) => e.apply_to(state),
            Self::Dip(e) => e.apply_to(state),
            Self::Drt(e) => e.apply_to(state),
            Self::Rct(e) => e.apply_to(state),
        }
    }
}

