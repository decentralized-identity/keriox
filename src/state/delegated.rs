use super::signatory::Signatory;
use crate::prefix::IdentifierPrefix;

#[derive(Default, PartialEq, Debug, Clone)]
pub struct DelegatedIdentifierState {
    pub prefix: IdentifierPrefix,
    pub sn: u64,
    pub perms: String,
    pub signatory: Signatory,
}
