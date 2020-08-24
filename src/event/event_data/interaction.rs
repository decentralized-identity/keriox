use crate::state::EventSemantics;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InteractionEvent {}

impl EventSemantics for InteractionEvent {}
