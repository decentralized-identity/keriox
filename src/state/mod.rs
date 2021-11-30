use crate::{error::Error, event::{sections::KeyConfig, EventMessage, Event}, prefix::{BasicPrefix, IdentifierPrefix, Prefix, SelfAddressingPrefix}};
use serde::{Deserialize, Serialize, Serializer};


#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct LastEstablishmentData {
	#[serde(rename = "s")]
	pub(crate) sn: u64,
	#[serde(rename = "d")]
	pub(crate) digest: SelfAddressingPrefix,
	pub(crate) br: Vec<BasicPrefix>,
	pub(crate) ba: Vec<BasicPrefix>,
}

/// Identifier State
///
/// represents the accumulated state after applying events, based on section 13 of the paper
#[derive(Default, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct IdentifierState {
    #[serde(rename = "i")] 
    pub prefix: IdentifierPrefix,
    #[serde(rename = "s")] 
    pub sn: u64,
    #[serde(skip)]
    pub last: EventMessage<Event>,
    #[serde(flatten)] 
    pub current: KeyConfig,
    #[serde(skip)] 
    pub delegates: Vec<IdentifierPrefix>,
    #[serde(rename = "bt")] 
    pub tally: u64,
    #[serde(rename = "b")] 
    pub witnesses: Vec<BasicPrefix>,
    #[serde(rename = "di", serialize_with = "serialize_default")] 
    pub delegator: Option<IdentifierPrefix>,
	#[serde(rename = "ee")]
    pub last_est: LastEstablishmentData,
}

fn serialize_default<S>(x: &Option<IdentifierPrefix>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&(x.clone().unwrap_or_default()).to_str())
}

impl IdentifierState {
    /// Apply
    ///
    /// validates and applies the semantic rules of the event to the event state
    pub fn apply<T: EventSemantics>(self, event: &T) -> Result<Self, Error> {
        event.apply_to(self)
    }
}

/// EventSemantics
///
/// Describes an interface for applying the semantic rule of an event to the state of an Identifier
pub trait EventSemantics {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        // default impl is the identity transition
        Ok(state)
    }
}
