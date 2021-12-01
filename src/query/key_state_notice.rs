use chrono::{DateTime, FixedOffset, Utc};
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};

use crate::{
    derivation::self_addressing::SelfAddressing,
    event::{
        event_data::{DummyEvent, EventData},
        EventMessage, SerializationFormats,
    },
    prefix::{Prefix, SelfAddressingPrefix},
    state::IdentifierState,
};

// # {
// #   "v":"KERI10JSON000294_",
// #   "t":"rpy",
// #   "d":"EPeNPAtRcVjY7lLxl_DZ3qFPb0R0n_6wmGAMgO-u8_YU",
// #   "dt":"2021-01-01T00:00:00.000000+00:00",
// #   "r":"/ksn/BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY",
// #   "a":{
// #     "v":"KERI10JSON0001d9_",
// #     "i":"E4BsxCYUtUx3d6UkDVIQ9Ke3CLQfqWBfICSmjIzkS1u4",
// #     "s":"0",
// #     "p":"",
// #     "d":"EYk4PigtRsCd5W2so98c8r8aeRHoixJK7ntv9mTrZPmM",
// #     "f":"0",
// #     "dt":"2021-01-01T00:00:00.000000+00:00",
// #     "et":"icp",
// #     "kt":"1",
// #     "k":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],
// #     "n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss",
// #     "bt":"1",
// #     "b":["BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY"],
// #     "c":[],
// #     "ee":{
// #       "s":"0",
// #       "d":"EYk4PigtRsCd5W2so98c8r8aeRHoixJK7ntv9mTrZPmM",
// #       "br":[],
// #       "ba":[]
// #     },
// #     "di":""
// #   }
// # }
// # -VAi-CABBFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY0B8nPsrW2sCoJ9JA_MaghAUxQPXZV94p8Jv_Ex_JV1zNyNlSPUTlUAAqZwaUf0ijY8ETqSgOi9z5tTv0POovmUDQ

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct KeyStateNotice {
    #[serde(flatten)]
    state: IdentifierState,

    #[serde(rename = "f")]
    first_seen_sn: u64,

    #[serde(rename = "p")]
    previous: Option<SelfAddressingPrefix>,

    #[serde(rename = "dt")]
    timestamp: DateTime<FixedOffset>,

    #[serde(rename = "d")]
    digest: Option<SelfAddressingPrefix>, // digest of latest (current) event

    #[serde(rename = "et")]
    event_data: EventType,

    #[serde(rename = "c")]
    config: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum EventType {
    Icp,
    Rot,
    Ixn,
    Dip,
    Drt,
    Rct,
}

impl From<&EventData> for EventType {
    fn from(ed: &EventData) -> Self {
        match ed {
            EventData::Icp(_) => EventType::Icp,
            EventData::Rot(_) => EventType::Rot,
            EventData::Ixn(_) => EventType::Ixn,
            EventData::Dip(_) => EventType::Dip,
            EventData::Drt(_) => EventType::Drt,
            EventData::Rct(_) => EventType::Rct,
        }
    }
}

impl Serialize for KeyStateNotice {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let digest = match &self.digest {
            Some(sai) => sai.to_str(),
            // TODO shouldn't be set to Blake3_265
            None => DummyEvent::dummy_prefix(&SelfAddressing::Blake3_256),
        };
        let mut em = serializer.serialize_struct("Envelope", 15)?;
        em.serialize_field("i", &self.state.prefix)?;
        em.serialize_field("s", &self.state.sn)?;
        em.serialize_field("p", &self.previous.clone().unwrap_or_default())?;
        em.serialize_field("d", &digest)?;
        em.serialize_field("f", &self.first_seen_sn)?;
        em.serialize_field("dt", &self.timestamp)?;
        em.serialize_field("et", &self.event_data)?;
        em.serialize_field("kt", &self.state.current.threshold)?;
        em.serialize_field("k", &self.state.current.public_keys)?;
        em.serialize_field(
            "n",
            &self.state.current.threshold_key_digest.clone().unwrap(),
        )?;
        em.serialize_field("bt", &self.state.tally)?;
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
        let previous = match state.last.event.event_data.clone() {
            EventData::Icp(_) => None,
            EventData::Rot(rot) => Some(rot.previous_event_hash),
            EventData::Ixn(ixn) => Some(ixn.previous_event_hash),
            EventData::Dip(_) => None,
            EventData::Drt(drt) => Some(drt.previous_event_hash),
            EventData::Rct(_) => todo!(),
        };

        let event_data = EventType::from(&state.last.event.event_data);

        let ksn = KeyStateNotice {
            timestamp: dt,
            state,
            previous,
            digest: None,
            first_seen_sn: 0,
            event_data,
            config: vec![],
        };
        // Compute digest of event with dummy digest
        let ev_msg = EventMessage::new(ksn.clone(), serialization).unwrap();
        let dig = derivation.derive(&ev_msg.serialize().unwrap());
        let hashed_ksn = KeyStateNotice {
            digest: Some(dig),
            ..ksn.clone()
        };
        EventMessage {
            event: hashed_ksn,
            ..ev_msg
        }
    }
}

#[test]
pub fn test() {
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
