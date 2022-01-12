use super::EventData;
use super::InceptionEvent;
use crate::event_message::KeyEvent;
use crate::event_message::SaidEvent;
use crate::event_message::dummy_event::DummyInceptionEvent;
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
    ) -> Result<EventMessage<KeyEvent>, Error> {
        let dummy_event = DummyInceptionEvent::dummy_delegated_inception_data(self.clone(), &derivation, format)?;
        let digest = derivation.derive(&dummy_event.serialize()?);
        let event = Event::new(
            IdentifierPrefix::SelfAddressing(digest.clone()),
            0,
            EventData::Dip(self),
        );
        Ok(EventMessage {
            serialization_info: dummy_event.serialization_info,
            event: SaidEvent::new(digest, event),
        })
    
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

#[test]
fn test_delegated_inception_data_derivation() -> Result<(), Error> {
    use crate::prefix::{BasicPrefix, Prefix};
    use crate::event::sections::{key_config::{nxt_commitment, KeyConfig}, threshold::SignatureThreshold};
    use crate::event_message::Digestible;

    // data taken from keripy/tests/core/test_delegation.py
    let keys: Vec<BasicPrefix> = vec![
        "DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3x5b1CJmuUphA"
            .parse()
            .unwrap(),
    ];
    let next_keys: Vec<BasicPrefix> = vec![
        "DTf6QZWoet154o9wvzeMuNhLQRr8JaAUeiC6wjB_4_08"
            .parse()
            .unwrap(),
    ];

    let next_key_hash = nxt_commitment(&SignatureThreshold::Simple(1), &next_keys, &SelfAddressing::Blake3_256);
    let key_config = KeyConfig::new(keys, Some(next_key_hash), Some(SignatureThreshold::Simple(1)));
    let dip_data = DelegatedInceptionEvent 
        {
            inception_data: InceptionEvent::new(key_config.clone(), None, None), 
            delegator: "Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8".parse()?
        }
        .incept_self_addressing(SelfAddressing::Blake3_256, SerializationFormats::JSON)?;

    assert_eq!("Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI", dip_data.event.get_prefix().to_str());
    assert_eq!("Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI", dip_data.event.get_digest().unwrap().to_str());
    assert_eq!("KERI10JSON000154_", dip_data.serialization_info.to_str());
    
    Ok(())
}