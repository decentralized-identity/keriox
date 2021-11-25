use crate::prefix::{AttachedSignaturePrefix, IdentifierPrefix};
use chrono::{DateTime, FixedOffset};
use serde::{ser::SerializeStruct, Deserialize, Serialize};

use self::query::QueryData;

pub mod query;

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct Envelope {
    #[serde(rename = "dt")]
    pub timestamp: DateTime<FixedOffset>,

    #[serde(rename = "r")]
    pub route: String,

    #[serde(rename = "t", flatten)]
    pub message: MessageType,
}

impl Serialize for Envelope {
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
			    em.serialize_field("rr", &qry_data.replay_route)?;
                em.serialize_field("q", &qry_data.data)?;
            }
        };
        em.end()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum MessageType {
    Qry(QueryData),
    // todo Rpy(ReplyData)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedEnvelope {
    pub envelope: Envelope,
    pub signer: IdentifierPrefix,
    pub signatures: Vec<AttachedSignaturePrefix>,
}

impl SignedEnvelope {
    pub fn new(
        envelope: Envelope,
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

#[test]
fn test_query_deserialize() {
    use crate::event_message::EventMessage;
    // From keripy
    let input_query = r#"{"v":"KERI10JSON00011c_","t":"qry","dt":"2020-08-22T17:50:12.988921+00:00","r":"logs","rr":"log/processor","q":{"i":"EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"}}"#;

    let qr: Result<EventMessage<Envelope>, _> = serde_json::from_str(input_query);
    assert!(qr.is_ok());

    let qr = qr.unwrap();

    assert_eq!(serde_json::to_string(&qr).unwrap(), input_query);
}
