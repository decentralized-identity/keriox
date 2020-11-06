use crate::prefix::BasicPrefix;
use serde::{Deserialize, Serialize};

#[derive(Default, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Signatory {
    pub threshold: u64,
    pub signers: Vec<BasicPrefix>,
}
