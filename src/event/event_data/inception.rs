use super::{
    super::sections::{InceptionWitnessConfig, KeyConfig},
    DummyEvent, EventData,
};
use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::Event,
    event_message::{serialization_info::SerializationFormats, EventMessage},
    prefix::IdentifierPrefix,
    state::{EventSemantics, IdentifierState},
};
use serde::{Deserialize, Serialize};

/// Inception Event
///
/// Describes the inception (icp) event data,
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InceptionEvent {
    #[serde(flatten)]
    pub key_config: KeyConfig,

    #[serde(flatten)]
    pub witness_config: InceptionWitnessConfig,

    #[serde(rename = "c")]
    pub inception_configuration: Vec<String>,
}

impl InceptionEvent {
    pub fn new(
        key_config: KeyConfig,
        witness_config: Option<InceptionWitnessConfig>,
        inception_config: Option<Vec<String>>,
    ) -> Self {
        Self {
            key_config,
            witness_config: witness_config.map_or_else(|| InceptionWitnessConfig::default(), |w| w),
            inception_configuration: inception_config.map_or_else(|| vec![], |c| c),
        }
    }

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
                    &DummyEvent::derive_inception_data(self.clone(), derivation, format)?,
                )),
                sn: 0,
                event_data: EventData::Icp(self),
            },
            format,
        )
    }
}

impl EventSemantics for InceptionEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        Ok(IdentifierState {
            current: self.key_config.clone(),
            witnesses: self.witness_config.initial_witnesses.clone(),
            tally: self.witness_config.tally,
            ..state
        })
    }
}
