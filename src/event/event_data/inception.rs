use super::{
    super::sections::{InceptionWitnessConfig, KeyConfig},
    DummyEvent, EventData,
};
use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::{sections::seal::Seal, Event},
    event_message::{serialization_info::SerializationFormats, EventMessage},
    prefix::IdentifierPrefix,
    state::{EventSemantics, IdentifierState, LastEstablishmentData},
};
use serde::{Deserialize, Serialize};

/// Inception Event
///
/// Describes the inception (icp) event data,
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct InceptionEvent {
    #[serde(flatten)]
    pub key_config: KeyConfig,

    #[serde(flatten)]
    pub witness_config: InceptionWitnessConfig,

    #[serde(rename = "c")]
    pub inception_configuration: Vec<String>,

    #[serde(rename = "a")]
    pub data: Vec<Seal>,
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
            data: vec![],
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
    ) -> Result<EventMessage<Event>, Error> {
        EventMessage::new(
            Event {
                prefix: IdentifierPrefix::SelfAddressing(derivation.derive(
                    &DummyEvent::derive_inception_data(self.clone(), &derivation, format)?,
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
        let last_est = LastEstablishmentData { 
            sn: state.sn, 
            digest: SelfAddressing::Blake3_256.derive(&state.last.serialize()?), 
            br: vec![], 
            ba: vec![] 
        };
        Ok(IdentifierState {
            current: self.key_config.clone(),
            witnesses: self.witness_config.initial_witnesses.clone(),
            tally: self.witness_config.tally,
            last_est,
            ..state
        })
    }
}
