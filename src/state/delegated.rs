use super::signatory::Signatory;
use crate::prefix::IdentifierPrefix;
use serde::{Deserialize, Serialize};

#[derive(Default, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedIdentifierState {
    pub prefix: IdentifierPrefix,
    pub sn: u64,
    pub perms: String,
    pub signatory: Signatory,
}
