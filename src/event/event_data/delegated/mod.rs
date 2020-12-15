use super::super::sections::seal::LocationSeal;
use super::{InceptionEvent, RotationEvent};
use crate::state::EventSemantics;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DelegatedInceptionEvent {
    #[serde(flatten)]
    pub inception_data: InceptionEvent,

    pub perm: Vec<String>,

    pub seal: LocationSeal,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DelegatedRotationEvent {
    #[serde(flatten)]
    pub rotation_data: RotationEvent,

    pub perm: Vec<String>,

    pub seal: LocationSeal,
}

impl EventSemantics for DelegatedInceptionEvent {}
impl EventSemantics for DelegatedRotationEvent {}
