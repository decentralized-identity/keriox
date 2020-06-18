pub mod delegated;
pub mod inception;
pub mod interaction;
pub mod receipt;
pub mod rotation;

use crate::error::Error;
use crate::state::IdentifierState;
use serde::{Deserialize, Serialize};

use self::{
    delegated::{DelegatedInceptionEvent, DelegatedRotationEvent},
    inception::InceptionEvent,
    interaction::InteractionEvent,
    receipt::EventReceipt,
    rotation::RotationEvent,
};

#[derive(Serialize, Deserialize)]
#[serde(tag = "ilk", rename_all = "lowercase")]
pub enum EventData {
    Icp(InceptionEvent),
    Rot(RotationEvent),
    Ixn(InteractionEvent),
    Dip(DelegatedInceptionEvent),
    Drt(DelegatedRotationEvent),
    Rct(EventReceipt),
}

pub trait EventSemantics {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        Ok(state)
    }
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
