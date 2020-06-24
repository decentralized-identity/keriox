use crate::prefix::Prefix;

#[derive(Default, PartialEq, Debug)]
pub struct Signatory {
    pub threshold: usize,
    pub signers: Vec<Prefix>,
}
