use crate::prefix::Prefix;

#[derive(Default, PartialEq)]
pub struct Signatory {
    threshold: u64,
    signers: Vec<Prefix>,
}
