use super::super::sections::seal::LocationSeal;
use super::{InceptionEvent, RotationEvent};
use crate::{
    error::Error,
    state::{EventSemantics, IdentifierState},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DelegatedInceptionEvent {
    #[serde(flatten)]
    pub inception_data: InceptionEvent,

    pub seal: LocationSeal,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DelegatedRotationEvent {
    #[serde(flatten)]
    pub rotation_data: RotationEvent,

    pub perm: Vec<String>,

    pub seal: LocationSeal,
}

impl EventSemantics for DelegatedInceptionEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        Ok(IdentifierState {
            delegator: Some(self.seal.prefix.clone()),
            ..self.inception_data.apply_to(state)?
        })
    }
}
impl EventSemantics for DelegatedRotationEvent {}
