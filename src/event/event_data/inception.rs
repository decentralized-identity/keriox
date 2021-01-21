use super::{
    super::sections::{InceptionWitnessConfig, KeyConfig},
    EventData,
};
use crate::{
    derivation::{self_addressing::SelfAddressing, DerivationCode},
    error::Error,
    event::Event,
    event_message::{
        serialization_info::{SerializationFormats, SerializationInfo},
        EventMessage,
    },
    prefix::IdentifierPrefix,
    state::{EventSemantics, IdentifierState},
};
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};

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
                prefix: DummyInceptionEvent::derive(self.clone(), derivation, format)?,
                sn: 0,
                event_data: EventData::Icp(self),
            },
            format,
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DummyInceptionEvent {
    #[serde(rename = "v")]
    serialization_info: SerializationInfo,
    #[serde(rename = "i")]
    prefix: String,
    #[serde(rename = "s", with = "SerHex::<Compact>")]
    sn: u8,
    #[serde(flatten)]
    icp_data: InceptionEvent,
}

impl DummyInceptionEvent {
    pub fn derive(
        icp: InceptionEvent,
        derivation: SelfAddressing,
        format: SerializationFormats,
    ) -> Result<IdentifierPrefix, Error> {
        Ok(IdentifierPrefix::SelfAddressing(
            derivation.derive(
                &Self {
                    serialization_info: SerializationInfo::new(
                        format,
                        Self {
                            serialization_info: SerializationInfo::new(format, 0),
                            prefix: Self::dummy_prefix(derivation),
                            sn: 0,
                            icp_data: icp.clone(),
                        }
                        .serialize()?
                        .len(),
                    ),
                    prefix: Self::dummy_prefix(derivation),
                    sn: 0,
                    icp_data: icp,
                }
                .serialize()?,
            ),
        ))
    }

    fn serialize(&self) -> Result<Vec<u8>, Error> {
        self.serialization_info.kind.encode(&self)
    }

    fn dummy_prefix(derivation: SelfAddressing) -> String {
        std::iter::repeat("#")
            .take(derivation.code_len() + derivation.derivative_b64_len())
            .collect::<String>()
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
