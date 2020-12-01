use crate::prefix::SelfAddressingPrefix;
use serde::{Deserialize, Serialize};

/// Non-Transferrable Receipt
///
/// A receipt created by an Identifier of a non-transferrable type.
/// Mostly intended for use by Witnesses.
/// NOTE: This receipt has a unique structure to it's appended
/// signatures
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReceiptNonTransferable {
    /// Receipted Event Digest
    ///
    /// A Qualified Digest of the event which this receipt is made for.
    #[serde(rename = "dig")]
    pub receipted_event_digest: SelfAddressingPrefix,
}
