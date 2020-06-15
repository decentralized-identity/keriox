use crate::prefix::Prefix;
use serde::{Deserialize, Serialize};
pub mod event_data;
pub mod sections;

use self::event_data::{
    delegated::{DelegatedInceptionEvent, DelegatedRotationEvent},
    inception::InceptionEvent,
    interaction::InteractionEvent,
    receipt::EventReceipt,
    rotation::RotationEvent,
};

#[derive(Serialize, Deserialize)]
pub struct Event {
    #[serde(rename(serialize = "id", deserialize = "id"))]
    pub prefix: Prefix,

    pub sn: u64,

    #[serde(flatten)]
    pub event_data: EventData,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "ilk")]
#[serde(rename_all = "lowercase")]
pub enum EventData {
    Icp(InceptionEvent),
    Rot(RotationEvent),
    Ixn(InteractionEvent),
    Dip(DelegatedInceptionEvent),
    Drt(DelegatedRotationEvent),
    Rct(EventReceipt),
}
