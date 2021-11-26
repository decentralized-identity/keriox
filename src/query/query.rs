use serde::{Deserialize, Serialize};

use crate::prefix::IdentifierPrefix;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryData {
    #[serde(rename = "rr")]
    pub reply_route: String,

    #[serde(rename = "q")]
    pub data: IdData,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IdData {
    pub i: IdentifierPrefix,
}
