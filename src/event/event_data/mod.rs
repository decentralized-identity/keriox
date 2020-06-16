pub mod delegated;
pub mod inception;
pub mod interaction;
pub mod receipt;
pub mod rotation;

use crate::state::AccumulatedEventState;
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
