use super::EventSemantics;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct InteractionEvent {}

impl EventSemantics for InteractionEvent {}
