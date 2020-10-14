use super::super::sections::seal::Seal;
use crate::prefix::SelfAddressingPrefix;
use crate::state::EventSemantics;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReceiptNonTransferable {}

impl EventSemantics for ReceiptNonTransferable {}

/// Validator Receipt
///
/// Event Receipt which is suitable for creation by Transferable
/// Identifiers. Provides both the signatures and a commitment to
/// the latest establishment event of the Validator.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReceiptTransferable {
    /// Receipted Event Digest
    ///
    /// A Qualified Digest of the event which this receipt is made for.
    #[serde(rename = "dig")]
    pub receipted_event_digest: SelfAddressingPrefix,

    /// Validator Location Seal
    ///
    /// An Event Seal which indicates the latest establishment event of
    /// the Validator when the Receipt was made
    #[serde(rename = "seal")]
    pub validator_location_seal: Seal,
}

impl EventSemantics for ReceiptTransferable {}
