use super::signatory::Signatory;
use crate::prefix::Prefix;

#[derive(Default, PartialEq)]
pub struct DelegatedIdentifierState {
    pub prefix: Prefix,
    pub sn: u64,
    pub perms: String,
    pub signatory: Signatory,
}
