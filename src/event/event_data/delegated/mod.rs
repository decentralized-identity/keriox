use super::{DummyEvent, EventData};
use super::{InceptionEvent, RotationEvent};
use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::{Event, EventMessage, SerializationFormats},
    prefix::IdentifierPrefix,
    state::{EventSemantics, IdentifierState},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DelegatedInceptionEvent {
    #[serde(flatten)]
    pub inception_data: InceptionEvent,

    #[serde(rename = "di")]
    pub delegator: IdentifierPrefix,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DelegatedRotationEvent {
    #[serde(flatten)]
    pub rotation_data: RotationEvent,
}

impl DelegatedInceptionEvent {
    /// Incept Self Addressing
    ///
    /// Takes the inception data and creates an EventMessage based on it, with
    /// using the given format and deriving a Self Addressing Identifier with the
    /// given derivation method
    pub fn incept_self_addressing(
        self,
        derivation: SelfAddressing,
        format: SerializationFormats,
    ) -> Result<EventMessage, Error> {
        EventMessage::new(
            Event {
                prefix: IdentifierPrefix::SelfAddressing(derivation.derive(
                    &DummyEvent::derive_delegated_inception_data(
                        self.clone(),
                        &derivation,
                        format,
                    )?,
                )),
                sn: 0,
                event_data: EventData::Dip(self),
            },
            format,
        )
    }
}

impl EventSemantics for DelegatedInceptionEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        Ok(IdentifierState {
            delegator: Some(self.delegator.clone()),
            ..self.inception_data.apply_to(state)?
        })
    }
}
impl EventSemantics for DelegatedRotationEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        // if state.delegator == Some(self.delegator.prefix.clone()) {
            self.rotation_data.apply_to(state)
        // } else {
            // Err(Error::SemanticError("Wrong delegator".into()))
        // }
    }
}
