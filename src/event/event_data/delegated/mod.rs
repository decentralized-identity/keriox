use crate::state::EventSemantics;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DelegatedInceptionEvent {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DelegatedRotationEvent {}

impl EventSemantics for DelegatedInceptionEvent {}
impl EventSemantics for DelegatedRotationEvent {}
