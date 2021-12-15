use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::{
        event_data::DummyEvent, EventMessage, SerializationFormats,
    },
    prefix::{IdentifierPrefix, Prefix},
};
use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use serde::{de, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};

use self::{
    query::QueryData,
    reply::{ReplyData, SignedReply},
};

use thiserror::Error;

pub mod key_state_notice;
pub mod query;
pub mod reply;

pub type TimeStamp = DateTime<FixedOffset>;

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct Envelope<D: Serialize> {
    #[serde(rename = "dt")]
    pub timestamp: DateTime<FixedOffset>,

    #[serde(rename = "r")]
    pub route: Route,

    #[serde(rename = "t", flatten)]
    pub data: D,
}

impl<D: Serialize> Envelope<D> {
    pub fn new(route: Route, data: D) -> Self {
        let timestamp: DateTime<FixedOffset> = Utc::now().into();
        Envelope {
            timestamp,
            route,
            data,
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
        em.serialize_field(
            "dt",
            &self.timestamp.to_rfc3339_opts(SecondsFormat::Micros, false),
        )?;
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
        em.serialize_field(
            "dt",
            &self.timestamp.to_rfc3339_opts(SecondsFormat::Micros, false),
        )?;
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

#[derive(Debug)]
pub enum ReplyType {
    Rep(SignedReply),
    Kel(Vec<u8>),
}


#[derive(Error, Debug)]
pub enum QueryError {
    #[error("Got stale key state notice")]
    StaleKsn,
    #[error("Got stale reply message")]
    StaleRpy,
    #[error("No previous reply in database")]
    NoSavedReply,
    #[error("Key state notice is newer than state in db")]
    ObsoleteKel,
    #[error("No key state notice is db")]
    MissingKsn,
    #[error("Incorrect event digest")]
    IncorrectDigest,
    #[error("Error: {0}")]
    Error(String),
}
