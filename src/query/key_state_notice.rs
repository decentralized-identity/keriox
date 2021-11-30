
use chrono::{DateTime, FixedOffset, Utc};
use serde::{Deserialize, Serialize, Serializer};

use crate::{event::{EventMessage, SerializationFormats}, prefix::{SelfAddressingPrefix, BasicPrefix, Prefix}, state::IdentifierState, derivation::self_addressing::SelfAddressing};

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct KeyStateNotice {
	#[serde(flatten)]
	state: IdentifierState,
	#[serde(rename = "f")]
	first_seen_sn: u64,
	#[serde(rename = "dt")]
	timestamp: DateTime<FixedOffset>,
	#[serde(rename = "d", serialize_with = "serialize_digest")]
	digest: Option<SelfAddressingPrefix>, // digest of latest (current) event
	#[serde(rename = "et")]
	event_data: String, // ?,
	#[serde(rename = "c")]
	config: Vec<String>,
	#[serde(rename = "ee")]
	ee: LastEstablishmentData, // ?
}

fn serialize_digest<S>(x: &Option<SelfAddressingPrefix>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
	use crate::event::event_data::DummyEvent;
	s.serialize_str(
	&match x {
    Some(sai) => sai.to_str(),
	// TODO shouldn't be set to Blake3_265
    None => DummyEvent::dummy_prefix(&SelfAddressing::Blake3_256),
}
)
}

impl EventMessage<KeyStateNotice> {
	pub fn new_ksn(state: IdentifierState, serialization: SerializationFormats, derivation: SelfAddressing) -> Self {
		let dt: DateTime<FixedOffset> = DateTime::from(Utc::now());
		// TODO get last establishment event somehow
		let last_est = LastEstablishmentData { sn: 0, digest: SelfAddressingPrefix::default(), br: vec![], ba: vec![] };
	
        let ksn = KeyStateNotice { 
			timestamp: dt, 
			state, 
			digest: None, 
			first_seen_sn: 0, 
			event_data: "icp".into(), 
			config: vec![], 
			ee: last_est 
		};
		// Compute digest of event with dummy digest
		let ev_msg = EventMessage::new(ksn.clone(), serialization).unwrap();
		let dig = derivation.derive(&ev_msg.serialize().unwrap());
		let hashed_ksn = KeyStateNotice {digest: Some(dig), ..ksn.clone()};
		EventMessage {event: hashed_ksn, ..ev_msg}
    }
	
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LastEstablishmentData {
	#[serde(rename = "s")]
	sn: u64,
	#[serde(rename = "d")]
	digest: SelfAddressingPrefix,
	br: Vec<BasicPrefix>,
	ba: Vec<BasicPrefix>,
}

#[test]
pub fn test() {
	use std::{sync::Arc, convert::TryFrom};
	use crate::{database::sled::SledEventDatabase, processor::EventProcessor, event_parsing::message::signed_event_stream, event_message::signed_event_message::Message};
    
    use tempfile::Builder;
	// Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    std::fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
	let processor = EventProcessor::new(db);
	
	let kel = r#"{"v":"KERI10JSON0000ed_","i":"DgjNPg1vfa0Vv8yOQ6WFoW9YrN27zIYIFuf4Bp4JT2xQ","s":"0","t":"icp","kt":"1","k":["DgjNPg1vfa0Vv8yOQ6WFoW9YrN27zIYIFuf4Bp4JT2xQ"],"n":"EXpCMmEKTUa461RHSkPEruTDnqgsIN9jY86V9wzmEzgI","bt":"0","b":[],"c":[],"a":[]}-AABAAWZTeQvpsFn9RgCHHjAH7D-mpPgDHnQUD79Ct51BZfAaNfyqieWv2H_8zAJ5ZbfQTYUb1cpy21P3jtUAF6aGtAQ{"v":"KERI10JSON000122_","i":"DgjNPg1vfa0Vv8yOQ6WFoW9YrN27zIYIFuf4Bp4JT2xQ","s":"1","t":"rot","p":"EVnjT5yjnRibqED3oGGNmBPKFNiJOhGyUk5vyUtQqT1Y","kt":"1","k":["De0Oy-xv9qaT8OHD8TPmFaBa7PyIR1l-yHMLCoEYaMLU"],"n":"Ey8jkHy2p9yy2MoELRhdUMrnAbUDqxb2uzqjSX_Yf_2U","bt":"0","br":[],"ba":[],"a":[]}-AABAAd7ashJUZgusrUgG0xiDtG4ku1rkFf5uZwWaYkQRT8xflOIYbAJa3Lr0qJudLNTiNLMENQCRIIm1A62L9aD6CAA{"v":"KERI10JSON000098_","i":"DgjNPg1vfa0Vv8yOQ6WFoW9YrN27zIYIFuf4Bp4JT2xQ","s":"2","t":"ixn","p":"E4SQsvYxNc8Yp5GTEyfK8MX1frS_SIhGvpE08ArIgVgE","a":[]}-AABAAHvc4ChFCqXbqQYi1FxX819t3iZ8XVrfPiGoOjEokggnTuqdvUUVLJ6e3z4Ujl9fYBJp7csAGxuw0fSIehxCBAw"#;
	let kel = signed_event_stream(kel.as_bytes()).unwrap().1
		.into_iter()
		.map(|ev| Message::try_from(ev).unwrap());

	let mut state = IdentifierState::default();
	for msg in kel { 
		state = processor.process(msg).unwrap().unwrap();
	};

	let ksn = EventMessage::new_ksn(state, SerializationFormats::JSON, SelfAddressing::Blake3_256);

	println!("\n{}\n", serde_json::to_string(&ksn).unwrap());
	let exp = r#"{"v":"KERI10JSON0001d9_","i":"E4BsxCYUtUx3d6UkDVIQ9Ke3CLQfqWBfICSmjIzkS1u4","s":"0","p":"","d":"EYk4PigtRsCd5W2so98c8r8aeRHoixJK7ntv9mTrZPmM","f":"0","dt":"2021-01-01T00:00:00.000000+00:00","et":"icp","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss","bt":"1","b":["BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY"],"c":[],"ee":{"s":"0","d":"EYk4PigtRsCd5W2so98c8r8aeRHoixJK7ntv9mTrZPmM","br":[],"ba":[]},"di":""}"#;
	println!("{}\n", exp);

}