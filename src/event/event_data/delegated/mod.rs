use super::super::sections::seal::LocationSeal;
use super::{InceptionEvent, RotationEvent};
use crate::state::EventSemantics;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DelegatedInceptionEvent {
    #[serde(flatten)]
    inception_data: InceptionEvent,

    perm: Vec<String>,

    seal: LocationSeal,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DelegatedRotationEvent {
    #[serde(flatten)]
    rotation_data: RotationEvent,

    perm: Vec<String>,

    seal: LocationSeal,
}

impl EventSemantics for DelegatedInceptionEvent {}
impl EventSemantics for DelegatedRotationEvent {}
