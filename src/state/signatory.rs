use crate::prefix::BasicPrefix;

#[derive(Default, PartialEq, Debug, Clone)]
pub struct Signatory {
    pub threshold: u64,
    pub signers: Vec<BasicPrefix>,
}
