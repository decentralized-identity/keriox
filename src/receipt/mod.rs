pub mod nontransferable;
pub mod transferable;

use crate::{
    event_message::Message,
    prefix::{AttachedSignaturePrefix, IdentifierPrefix, SelfSigningPrefix},
};
pub use nontransferable::ReceiptNonTransferable;
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};
pub use transferable::ReceiptTransferable;

/// Receipt
///
/// A Receipt is a commitment to a Key Event made by either a
/// Witness or a Validator.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Receipt {
    /// Receipted Prefix
    ///
    /// Prefix Identifier of the event this receipt is for
    #[serde(rename = "pre")]
    pub receipted_prefix: IdentifierPrefix,

    /// Receipted Sequence Number
    ///
    /// SN of the event this receipt is for
    #[serde(with = "SerHex::<Compact>")]
    pub receipted_sn: u64,

    /// Receipt Data
    ///
    /// Data committing to the attributes of the
    /// receipt creator
    #[serde(flatten)]
    pub receipt_data: ReceiptData,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "ilk", rename_all = "lowercase")]
pub enum ReceiptData {
    Rct(ReceiptNonTransferable),
    Vrc(ReceiptTransferable),
}

pub type ReceiptMessage = Message<Receipt>;

// these two signed types are different because of the different
// structure of the signatures
pub struct SignedTransferableReceiptMessage {
    pub receipt_message: ReceiptMessage,
    pub signatures: Vec<AttachedSignaturePrefix>,
}

pub struct SignedNontransferableReceiptMessage {
    pub receipt_message: ReceiptMessage,
    pub signature_couplets: (IdentifierPrefix, SelfSigningPrefix),
}
