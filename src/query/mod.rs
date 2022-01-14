use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::{EventMessage, SerializationFormats},
    event_message::{SaidEvent, Typeable, EventTypeTag},
    prefix::{IdentifierPrefix, Prefix},
};
use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use self::reply::SignedReply;

use thiserror::Error;

pub mod key_state_notice;
pub mod query;
pub mod reply;

pub type TimeStamp = DateTime<FixedOffset>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Envelope<D: Serialize + Typeable> {
    #[serde(rename = "dt", serialize_with = "serialize_timestamp")]
    pub timestamp: DateTime<FixedOffset>,

    #[serde(rename = "r")]
    pub route: Route,

    #[serde(flatten)]
    pub data: D,
}

fn serialize_timestamp<S>(timestamp: &DateTime<FixedOffset>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&timestamp.to_rfc3339_opts(SecondsFormat::Micros, false))
}

impl<D: Serialize + Typeable + Clone> Envelope<D> {
    pub fn new(route: Route, data: D) -> Self {
        let timestamp: DateTime<FixedOffset> = Utc::now().into();
        Envelope {
            timestamp,
            route,
            data,
        }
    }

    fn to_message(
        self,
        format: SerializationFormats,
        derivation: &SelfAddressing,
    ) -> Result<EventMessage<SaidEvent<Envelope<D>>>, Error> {
        SaidEvent::<Self>::to_message(self, format, derivation)
    }
}

impl<D: Serialize + Typeable> Typeable for Envelope<D> {
    fn get_type(&self) -> EventTypeTag {
        self.data.get_type()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Route {
    Log,
    Ksn,
    ReplyKsn(IdentifierPrefix),
}

impl Serialize for Route {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&match self {
            Route::Log => "log".into(),
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
                "log" => Ok(Route::Log),
                _ => Err(Error::SemanticError("".into())).map_err(de::Error::custom),
            }
        }
    }
}

#[derive(Debug)]
pub enum ReplyType {
    Rep(SignedReply),
    Kel(Vec<u8>),
}

#[derive(Error, Debug)]
pub enum QueryError {
    #[error("Out of order query event")]
    OutOfOrderEventError,
    #[error("Got stale key state notice")]
    StaleKsn,
    #[error("Got stale reply message")]
    StaleRpy,
    #[error("No previous reply in database")]
    NoSavedReply,
    #[error("Incorrect event digest")]
    IncorrectDigest,
    #[error("Error: {0}")]
    Error(String),
}
