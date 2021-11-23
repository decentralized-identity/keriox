use crate::{event_message::serialization_info::SerializationInfo, prefix::{AttachedSignaturePrefix, IdentifierPrefix}};
use chrono::{DateTime, FixedOffset};
use serde::{ser::SerializeStruct, Deserialize, Serialize};

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct Envelope<D> {
    #[serde(rename = "dt")]
    pub timestamp: DateTime<FixedOffset>,

    #[serde(rename = "r")]
    pub route: String,

    #[serde(rename = "t", flatten)]
    pub message: MessageType<D>,
}

impl<D: Serialize> Serialize for Envelope<D> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut em = serializer.serialize_struct("Envelope", 5)?;
        match self.message {
            MessageType::Qry(ref qry_data) => {
                em.serialize_field("t", "qry")?;
                em.serialize_field("dt", &self.timestamp)?;
                em.serialize_field("r", &self.route)?;
                em.serialize_field("rr", &qry_data.reply_route)?;
                em.serialize_field("q", &qry_data.data)?;
            }
        };
        em.end()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum MessageType<D> {
    Qry(QueryData<D>),
    // todo Rpy(ReplyData)
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryData<D> {
    #[serde(rename = "rr")]
    pub reply_route: String,

    #[serde(rename = "q")]
    pub data: D,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IdData {
    pub i: IdentifierPrefix,
}

impl IdData {
    pub fn get_id(&self) -> IdentifierPrefix {
        self.i.clone()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedEnvelope<D> {
    pub envelope: Envelope<D>,
    pub signer: IdentifierPrefix,
    pub signatures: Vec<AttachedSignaturePrefix>,
}

impl<D> SignedEnvelope<D> {
    pub fn new(envelope: Envelope<D>, signer: IdentifierPrefix, signatures: Vec<AttachedSignaturePrefix>) -> Self {
        Self {envelope, signer, signatures}
    }
}

#[test]
fn test_query_parsing() {
    // From keripy
    let input_query = r#"{"v":"KERI10JSON00011c_","t":"qry","dt":"2020-08-22T17:50:12.988921+00:00","r":"logs","rr":"log/processor","q":{"i":"EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"}}"#;

    let qr: Result<Envelope<IdData>, _> = serde_json::from_str(input_query);
    assert!(qr.is_ok());

    let qr = qr.unwrap();

    assert_eq!(serde_json::to_string(&qr).unwrap(), input_query);
}
