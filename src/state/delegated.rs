use super::signatory::Signatory;
use crate::prefix::Prefix;

#[derive(Default, PartialEq)]
pub struct DelegatedIdentifierState {
    prefix: Prefix,
    sn: u64,
    perms: String,
    signatory: Signatory,
}
