use serde::{Serialize, Deserialize};

use crate::{event::sections::seal::EventSeal, prefix::{AttachedSignaturePrefix, SelfSigningPrefix, BasicPrefix, IdentifierPrefix}};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Signature {
    Transferable(EventSeal, Vec<AttachedSignaturePrefix>),
    NonTransferable(BasicPrefix, SelfSigningPrefix),
}

impl Signature {
    pub fn get_signer(&self) -> IdentifierPrefix {
        match self {
            Signature::Transferable(seal, _) => seal.prefix.clone(),
            Signature::NonTransferable(id, _) => IdentifierPrefix::Basic(id.clone()),
        }
    }
}
