pub mod delegated;
pub mod inception;
pub mod interaction;
pub mod receipt;
pub mod rotation;

use crate::error::Error;
use crate::state::{EventSemantics, IdentifierState};
use serde::{Deserialize, Serialize};

use self::{
    delegated::{DelegatedInceptionEvent, DelegatedRotationEvent},
    inception::InceptionEvent,
    interaction::InteractionEvent,
    receipt::{ReceiptNonTransferable, ReceiptTransferable},
    rotation::RotationEvent,
};

/// Event Data
///
/// Event Data conveys the semantic content of a KERI event.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "ilk", rename_all = "lowercase")]
pub enum EventData {
    Icp(InceptionEvent),
    Rot(RotationEvent),
    Ixn(InteractionEvent),
    Dip(DelegatedInceptionEvent),
    Drt(DelegatedRotationEvent),
    Rct(ReceiptNonTransferable),
    Vrc(ReceiptTransferable),
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
            Self::Vrc(e) => e.apply_to(state),
        }
    }
}
