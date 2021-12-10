use crate::{
    derivation::self_addressing::SelfAddressing,
    event::{event_data::DummyEvent, EventMessage, SerializationFormats, sections::seal::EventSeal},
    prefix::{AttachedSignaturePrefix, IdentifierPrefix, Prefix, BasicPrefix, SelfSigningPrefix}, error::Error,
};
use chrono::{DateTime, FixedOffset, Utc, SecondsFormat};
use serde::{
    ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer, de,
};

use self::{key_state_notice::KeyStateNotice, query::QueryData, reply::ReplyData};

use thiserror::Error;

pub mod key_state_notice;
pub mod query;
pub mod reply;

pub type TimeStamp = DateTime<FixedOffset>;

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct Envelope<D> {
    #[serde(rename = "dt")]
    pub timestamp: DateTime<FixedOffset>,

    #[serde(rename = "r")]
    pub route: Route,

    #[serde(rename = "t", flatten)]
    pub data: D,
}

impl<D> Envelope<D> {
    pub fn new(route: Route, data: D) -> Self {
        let timestamp : DateTime<FixedOffset> = Utc::now().into();
        Envelope {
            timestamp,
            route, 
            data
        }
    }
}

impl Envelope<ReplyData> {
     pub fn to_message(self, format: SerializationFormats) -> Result<EventMessage<Self>, Error> {
        EventMessage::new(self, format)
    }
}

impl Envelope<QueryData> {
     pub fn to_message(self, format: SerializationFormats) -> Result<EventMessage<Self>, Error> {
        EventMessage::new(self, format)
    }
}

pub fn new_reply(
    ksn: EventMessage<KeyStateNotice>,
    route: Route,
    self_addressing: SelfAddressing,
) -> EventMessage<Envelope<ReplyData>> {
    // To create reply message we need to use dummy string in digest field,
    // compute digest and update d field.
    let rpy_data = ReplyData {
        digest: None,
        data: ksn.clone(),
    };
    let env = Envelope {
        timestamp: Utc::now().into(),
        route: route.clone(),
        data: rpy_data,
    };
    let ev_msg = EventMessage::new(env.clone(), SerializationFormats::JSON).unwrap();
    let dig = self_addressing.derive(&ev_msg.serialize().unwrap());
    let version = ev_msg.serialization_info;
    let rpy_data = ReplyData {
        digest: Some(dig),
        data: ksn,
    };
    let env = Envelope {
        data: rpy_data,
        ..env
    };
    EventMessage {
        serialization_info: version,
        event: env,
    }
}
 impl Serialize for Envelope<ReplyData> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut em = serializer.serialize_struct("Envelope", 5)?;
        let digest = match self.data.digest {
            Some(ref sai) => sai.to_str(),
            // TODO shouldn't be set to Blake3_265
            None => DummyEvent::dummy_prefix(&SelfAddressing::Blake3_256),
            };
        em.serialize_field("t", "rpy")?;
        em.serialize_field("d", &digest)?;
        em.serialize_field("dt", &self.timestamp.to_rfc3339_opts(SecondsFormat::Micros, false))?;
        em.serialize_field("r", &self.route)?;
        em.serialize_field("a", &self.data.data)?;
            
        em.end()
    }
}

impl Serialize for Envelope<QueryData> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut em = serializer.serialize_struct("Envelope", 5)?;
        em.serialize_field("t", "qry")?;
        em.serialize_field("dt", &self.timestamp.to_rfc3339_opts(SecondsFormat::Micros, false))?;
        em.serialize_field("r", &self.route)?;
        em.serialize_field("rr", &self.data.reply_route)?;
        em.serialize_field("q", &self.data.data)?;
        em.end()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Route {
    Logs,
    Ksn,
    ReplyKsn(IdentifierPrefix),
}

impl Serialize for Route {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&match self {
            Route::Logs => "logs".into(),
            Route::Ksn => "ksn".into(),
            Route::ReplyKsn(id) => ["/ksn/", &id.to_str()].join(""),
        })
    }
}

impl<'de> Deserialize<'de> for Route {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.starts_with("/ksn/") {
            let id: &IdentifierPrefix = &s[5..].parse().unwrap();
            Ok(Route::ReplyKsn(id.clone()))
        } else {
            match &s[..] {
                "ksn" => Ok(Route::Ksn),
                "logs" => Ok(Route::Logs),
                _ => Err(Error::SemanticError("".into())).map_err(de::Error::custom),
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Signature {
    Transferable(EventSeal, Vec<AttachedSignaturePrefix>),
    NonTransferable(BasicPrefix, SelfSigningPrefix),
}

impl Signature {
    pub fn get_signer(&self) -> IdentifierPrefix {
        match self {
            Signature::Transferable(seal, _) => seal.prefix.clone(),
            Signature::NonTransferable(id, _) => IdentifierPrefix::Basic(id.clone()),
        }
    }

    
}

pub type Reply = EventMessage<Envelope<ReplyData>>;

impl Reply {
    pub fn get_timestamp(&self) -> DateTime<FixedOffset> {
        self.event.timestamp
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SignedReply {
    pub reply: Reply,
    // pub signer: BasicPrefix,
    // pub signature: SelfSigningPrefix,
    pub signature: Signature,
}

impl SignedReply {
    pub fn new_nontrans(
        envelope: EventMessage<Envelope<ReplyData>>,
        signer: BasicPrefix,
        signature: SelfSigningPrefix,
    ) -> Self {
        let signature = Signature::NonTransferable(signer, signature);
        Self {
            reply: envelope,
            // signer,
            signature,
        }
    }

    pub fn new_trans(
        envelope: EventMessage<Envelope<ReplyData>>,
        signer_seal: EventSeal,
        signatures: Vec<AttachedSignaturePrefix>,
    ) -> Self {
        let signature = Signature::Transferable(signer_seal, signatures);
        Self {
            reply: envelope,
            signature,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedQuery {
    pub envelope: EventMessage<Envelope<QueryData>>,
    pub signer: IdentifierPrefix,
    pub signatures: Vec<AttachedSignaturePrefix>,
}

impl SignedQuery {
    pub fn new(
        envelope: EventMessage<Envelope<QueryData>>,
        signer: IdentifierPrefix,
        signatures: Vec<AttachedSignaturePrefix>,
    ) -> Self {
        Self {
            envelope,
            signer,
            signatures,
        }
    }
}

#[derive(Error, Debug)]
pub enum QueryError {
    #[error("Got stale key state notice")]
    StaleKsn,
    #[error("Got stale reply message")]
    StaleRpy,
    #[error("Key state notice is newer than state in db")]
    ObsoleteKel,
    #[error("No key state notice is db")]
    MissingKsn,
    #[error("Incorrect event digest")]
    IncorrectDigest,
    #[error("Error: {0}")]
    Error(String),
}

#[test]
fn test_query_deserialize() {
    use crate::event_message::EventMessage;
    let input_query = r#"{"v":"KERI10JSON00011c_","t":"qry","dt":"2020-08-22T17:50:12.988921+00:00","r":"ksn","rr":"route","q":{"i":"DQ0NRLhqsdR2KomXD9l8JWI-03OHAKnQHKEJSNj8qwhE"}}"#;

    let qr: Result<EventMessage<Envelope<QueryData>>, _> = serde_json::from_str(input_query);
    assert!(qr.is_ok());

    let qr = qr.unwrap();

    assert_eq!(serde_json::to_string(&qr).unwrap(), input_query);
}

#[test]
fn test_reply_deserialize() {
    use crate::event_message::EventMessage;
    // From keripy
    let rpy = r#"{"v":"KERI10JSON000294_","t":"rpy","d":"EPeNPAtRcVjY7lLxl_DZ3qFPb0R0n_6wmGAMgO-u8_YU","dt":"2021-01-01T00:00:00.000000+00:00","r":"/ksn/BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY","a":{"v":"KERI10JSON0001d9_","i":"E4BsxCYUtUx3d6UkDVIQ9Ke3CLQfqWBfICSmjIzkS1u4","s":"0","p":"","d":"EYk4PigtRsCd5W2so98c8r8aeRHoixJK7ntv9mTrZPmM","f":"0","dt":"2021-01-01T00:00:00.000000+00:00","et":"icp","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss","bt":"1","b":["BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY"],"c":[],"ee":{"s":"0","d":"EYk4PigtRsCd5W2so98c8r8aeRHoixJK7ntv9mTrZPmM","br":[],"ba":[]},"di":""}}"#;

    let qr: Result<EventMessage<Envelope<ReplyData>>, _> = serde_json::from_str(rpy);
    assert!(qr.is_ok());
    let qr = qr.unwrap();

    assert_eq!(serde_json::to_string(&qr).unwrap(), rpy);
}

