use crate::state::EventSemantics;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DelegatingInceptionEvent {}

impl EventSemantics for DelegatedInceptionEvent {}
