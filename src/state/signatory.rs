use crate::prefix::Prefix;

#[derive(Default, PartialEq)]
pub struct Signatory {
    pub threshold: u64,
    pub signers: Vec<Prefix>,
}
