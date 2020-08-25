use crate::prefix::BasicPrefix;

#[derive(Default, PartialEq, Debug)]
pub struct Signatory {
    pub threshold: u64,
    pub signers: Vec<BasicPrefix>,
}
