use serde::{Deserialize, Serialize};

use crate::prefix::IdentifierPrefix;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryData {
    #[serde(rename = "rr")]
    pub replay_route: String,

    #[serde(rename = "q")]
    pub data: IdData,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IdData {
    pub i: IdentifierPrefix,
}
