use serde::{Deserialize, Serialize};

use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::{EventMessage, SerializationFormats},
    event_message::{SaidEvent, Typeable},
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

pub type QueryEvent = SaidEvent<Envelope<QueryData>>;

impl QueryEvent {
    pub fn new_query(
        route: Route,
        id: &IdentifierPrefix,
        serialization_format: SerializationFormats,
        derivation: &SelfAddressing,
    ) -> Result<EventMessage<Self>, Error> {
        let message = QueryData {
            reply_route: "route".into(),
            data: QueryArgs { i: id.clone() },
        };

        let env = Envelope::new(route, message);
        env.to_message(serialization_format, derivation)
    }

    pub fn get_route(&self) -> Route {
        self.content.route.clone()
    }

    pub fn get_query_data(&self) -> QueryData {
        self.content.data.clone()
    }
}

impl Typeable for QueryData {
    fn get_type(&self) -> Option<String> {
        Some("qry".to_string())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SignedQuery {
    pub envelope: EventMessage<QueryEvent>,
    pub signer: IdentifierPrefix,
    pub signatures: Vec<AttachedSignaturePrefix>,
}

impl SignedQuery {
    pub fn new(
        envelope: EventMessage<QueryEvent>,
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
    // taken from keripy keripy/tests/core/test_eventing.py::test_messegize (line 1462)
    let input_query = r#"{"v":"KERI10JSON0000c9_","t":"qry","d":"E-WvgxrllmjGFhpn0oOiBkAVz3-dEm3bbiV_5qwj81xo","dt":"2021-01-01T00:00:00.000000+00:00","r":"log","rr":"","q":{"i":"DyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI"}}"#;
    let qr: Result<EventMessage<QueryEvent>, _> = serde_json::from_str(input_query);
    assert!(qr.is_ok());

    let qr = qr.unwrap();

    assert_eq!(serde_json::to_string(&qr).unwrap(), input_query);
}
