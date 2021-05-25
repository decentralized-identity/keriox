use crate::prefix::SelfAddressingPrefix;
use crate::state::EventSemantics;
use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Receipt {
    /// Receipted Event Digest
    ///
    /// A Qualified Digest of the event which this receipt is made for.
    #[serde(rename = "d")]
    pub receipted_event_digest: SelfAddressingPrefix,
}

impl EventSemantics for Receipt {}