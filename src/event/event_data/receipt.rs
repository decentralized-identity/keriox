use crate::state::EventSemantics;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct EventReceipt {}

impl EventSemantics for EventReceipt {}
