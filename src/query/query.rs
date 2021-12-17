use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    event::{EventMessage, SerializationFormats},
    prefix::{AttachedSignaturePrefix, IdentifierPrefix},
};

use super::{Envelope, Route};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryData {
    #[serde(rename = "rr")]
    pub reply_route: String,

    #[serde(rename = "q")]
    pub data: QueryArgs,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryArgs {
    pub i: IdentifierPrefix,
}

pub type Query = EventMessage<Envelope<QueryData>>;

impl Query {
    pub fn new_query(
        route: Route,
        id: &IdentifierPrefix,
        serialization_info: SerializationFormats,
    ) -> Result<Self, Error> {
        let message = QueryData {
            reply_route: "route".into(),
            data: QueryArgs { i: id.clone() },
        };

        Envelope::new(route, message).to_message(serialization_info)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SignedQuery {
    pub envelope: Query,
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

#[test]
fn test_query_deserialize() {
    let input_query = r#"{"v":"KERI10JSON00011c_","t":"qry","dt":"2020-08-22T17:50:12.988921+00:00","r":"ksn","rr":"route","q":{"i":"DQ0NRLhqsdR2KomXD9l8JWI-03OHAKnQHKEJSNj8qwhE"}}"#;

    let qr: Result<Query, _> = serde_json::from_str(input_query);
    assert!(qr.is_ok());

    let qr = qr.unwrap();

    assert_eq!(serde_json::to_string(&qr).unwrap(), input_query);
}
