use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use serde_hex::{Compact, SerHex};

use crate::{
    derivation::self_addressing::SelfAddressing,
    event::{EventMessage, SerializationFormats},
    prefix::SelfAddressingPrefix,
    state::IdentifierState,
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
    pub digest: SelfAddressingPrefix, // digest of latest (current) event

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

        EventMessage::new(ksn.clone(), serialization).unwrap()
    }
}

#[test]
pub fn test_ksn() {
    use crate::{
        database::sled::SledEventDatabase, event_message::signed_event_message::Message,
        event_parsing::message::signed_event_stream, processor::EventProcessor,
    };
    use std::{convert::TryFrom, sync::Arc};

    use tempfile::Builder;
    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    std::fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let processor = EventProcessor::new(db);

    let kel = r#"{"v":"KERI10JSON0000ed_","i":"DgjNPg1vfa0Vv8yOQ6WFoW9YrN27zIYIFuf4Bp4JT2xQ","s":"0","t":"icp","kt":"1","k":["DgjNPg1vfa0Vv8yOQ6WFoW9YrN27zIYIFuf4Bp4JT2xQ"],"n":"EXpCMmEKTUa461RHSkPEruTDnqgsIN9jY86V9wzmEzgI","bt":"0","b":[],"c":[],"a":[]}-AABAAWZTeQvpsFn9RgCHHjAH7D-mpPgDHnQUD79Ct51BZfAaNfyqieWv2H_8zAJ5ZbfQTYUb1cpy21P3jtUAF6aGtAQ{"v":"KERI10JSON000122_","i":"DgjNPg1vfa0Vv8yOQ6WFoW9YrN27zIYIFuf4Bp4JT2xQ","s":"1","t":"rot","p":"EVnjT5yjnRibqED3oGGNmBPKFNiJOhGyUk5vyUtQqT1Y","kt":"1","k":["De0Oy-xv9qaT8OHD8TPmFaBa7PyIR1l-yHMLCoEYaMLU"],"n":"Ey8jkHy2p9yy2MoELRhdUMrnAbUDqxb2uzqjSX_Yf_2U","bt":"0","br":[],"ba":[],"a":[]}-AABAAd7ashJUZgusrUgG0xiDtG4ku1rkFf5uZwWaYkQRT8xflOIYbAJa3Lr0qJudLNTiNLMENQCRIIm1A62L9aD6CAA{"v":"KERI10JSON000098_","i":"DgjNPg1vfa0Vv8yOQ6WFoW9YrN27zIYIFuf4Bp4JT2xQ","s":"2","t":"ixn","p":"E4SQsvYxNc8Yp5GTEyfK8MX1frS_SIhGvpE08ArIgVgE","a":[]}-AABAAHvc4ChFCqXbqQYi1FxX819t3iZ8XVrfPiGoOjEokggnTuqdvUUVLJ6e3z4Ujl9fYBJp7csAGxuw0fSIehxCBAw"#;
    let kel = signed_event_stream(kel.as_bytes())
        .unwrap()
        .1
        .into_iter()
        .map(|ev| Message::try_from(ev).unwrap());

    let mut state = IdentifierState::default();
    for msg in kel {
        state = processor.process(msg).unwrap().unwrap();
    }

    let ksn = EventMessage::new_ksn(
        state,
        SerializationFormats::JSON,
        SelfAddressing::Blake3_256,
    );

    println!("\n{}\n", serde_json::to_string(&ksn).unwrap());
}
