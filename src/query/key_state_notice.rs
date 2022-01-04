use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use serde_hex::{Compact, SerHex};

use crate::{
    derivation::self_addressing::SelfAddressing,
    event::{EventMessage, SerializationFormats},
    prefix::SelfAddressingPrefix,
    state::IdentifierState, event_message::CommonEvent,
};

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct KeyStateNotice {
    #[serde(flatten)]
    pub state: IdentifierState,

    #[serde(rename = "f", with = "SerHex::<Compact>")]
    first_seen_sn: u64,

    #[serde(rename = "dt")]
    pub timestamp: DateTime<FixedOffset>,

    #[serde(rename = "d")]
    pub digest: SelfAddressingPrefix, // digest of latest event from the state

    #[serde(rename = "c")]
    config: Vec<String>,
}

impl Serialize for KeyStateNotice {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut em = serializer.serialize_struct("Envelope", 15)?;
        em.serialize_field("i", &self.state.prefix)?;
        em.serialize_field("s", &self.state.sn.to_string())?;
        em.serialize_field("p", &self.state.last_previous.clone())?;
        em.serialize_field("d", &self.digest)?;
        em.serialize_field("f", &self.first_seen_sn.to_string())?;
        em.serialize_field(
            "dt",
            &self.timestamp.to_rfc3339_opts(SecondsFormat::Micros, false),
        )?;
        em.serialize_field("et", &self.state.last_event_type)?;
        em.serialize_field("kt", &self.state.current.threshold)?;
        em.serialize_field("k", &self.state.current.public_keys)?;
        em.serialize_field(
            "n",
            &self.state.current.threshold_key_digest.clone().unwrap(),
        )?;
        em.serialize_field("bt", &self.state.tally.to_string())?;
        em.serialize_field("b", &self.state.witnesses)?;
        em.serialize_field("c", &self.config)?;
        em.serialize_field("ee", &self.state.last_est)?;
        em.serialize_field("di", &self.state.delegator.clone().unwrap_or_default())?;
        em.end()
    }
}

impl EventMessage<KeyStateNotice> {
    pub fn new_ksn(
        state: IdentifierState,
        serialization: SerializationFormats,
        derivation: SelfAddressing,
    ) -> Self {
        let dt: DateTime<FixedOffset> = DateTime::from(Utc::now());

        let last_digest = derivation.derive(&state.last);
        let ksn = KeyStateNotice {
            timestamp: dt,
            state,
            digest: last_digest,
            first_seen_sn: 0,
            config: vec![],
        };

        EventMessage::new(ksn.clone(), serialization, &derivation).unwrap()
    }
}

impl CommonEvent for KeyStateNotice {
    fn get_type(&self) -> String {
        "qry".to_string()
    }
}