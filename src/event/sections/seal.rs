use crate::prefix::{IdentifierPrefix, SelfAddressingPrefix};
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Seal {
    Digest(DigestSeal),
    Root(RootSeal),
    Event(EventSeal),
    Location(LocationSeal),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DigestSeal {
    #[serde(rename = "dig")]
    pub dig: SelfAddressingPrefix,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RootSeal {
    #[serde(rename = "root")]
    pub tree_root: SelfAddressingPrefix,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EventSeal {
    #[serde(rename = "pre")]
    pub prefix: IdentifierPrefix,

    #[serde(rename = "dig")]
    pub event_digest: SelfAddressingPrefix,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocationSeal {
    #[serde(rename = "pre")]
    pub prefix: IdentifierPrefix,

    #[serde(with = "SerHex::<Compact>")]
    pub sn: u64,

    pub ilk: String,

    #[serde(rename = "dig")]
    pub prior_digest: SelfAddressingPrefix,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DelegatingEventSeal {
    #[serde(rename = "pre")]
    pub prefix: IdentifierPrefix,

    #[serde(rename = "dig")]
    pub commitment: SelfAddressingPrefix,
}
