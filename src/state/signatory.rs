use crate::prefix::Prefix;

#[derive(Default, PartialEq)]
pub struct Signatory {
    pub threshold: usize,
    pub signers: Vec<Prefix>,
}
