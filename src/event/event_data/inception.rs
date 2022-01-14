use super::{
    super::sections::{InceptionWitnessConfig, KeyConfig},
    EventData,
};
use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::{sections::seal::Seal, Event, KeyEvent},
    event_message::{serialization_info::SerializationFormats, EventMessage, dummy_event::DummyInceptionEvent, SaidEvent},
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
    ) -> Result<EventMessage<KeyEvent>, Error> {
        let dummy_event = DummyInceptionEvent::dummy_inception_data(self.clone(), &derivation, format)?;
        let digest = derivation.derive(&dummy_event.serialize()?);
        let event = Event::new(
            IdentifierPrefix::SelfAddressing(digest.clone()),
            0,
            EventData::Icp(self),
        );
        Ok(EventMessage {
            serialization_info: dummy_event.serialization_info,
            event: SaidEvent::new(digest, event),
        })
    }
}

impl EventSemantics for InceptionEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        let last_est = LastEstablishmentData { 
            sn: state.sn, 
            digest: state.last_event_digest.clone(), 
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

#[test]
fn test_inception_data_derivation() -> Result<(), Error> {
    use crate::prefix::{BasicPrefix, Prefix};
    use crate::event::sections::{key_config::{KeyConfig, nxt_commitment}, threshold::SignatureThreshold};
    use crate::event_message::Digestible;

    let keys: Vec<BasicPrefix> = vec![
        "DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"
            .parse()
            .unwrap(),
        "DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"
            .parse()
            .unwrap(),
        "DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"
            .parse()
            .unwrap(),
    ];
    let next_keys: Vec<BasicPrefix> = vec![
        "DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ"
            .parse()
            .unwrap(),
        "D1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU"
            .parse()
            .unwrap(),
        "D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM"
            .parse()
            .unwrap(),
    ];

    let next_key_hash = nxt_commitment(&SignatureThreshold::Simple(2), &next_keys, &SelfAddressing::Blake3_256);
    let key_config = KeyConfig::new(keys, Some(next_key_hash), Some(SignatureThreshold::Simple(2)));
    let icp_data = InceptionEvent::new(key_config.clone(), None, None)
        .incept_self_addressing(SelfAddressing::Blake3_256, SerializationFormats::JSON)?;

    assert_eq!("ELYk-z-SuTIeDncLr6GhwVUKnv3n3F1bF18qkXNd2bpk", icp_data.event.get_prefix().to_str());
    assert_eq!("ELYk-z-SuTIeDncLr6GhwVUKnv3n3F1bF18qkXNd2bpk", icp_data.event.get_digest().unwrap().to_str());
    
    Ok(())
}