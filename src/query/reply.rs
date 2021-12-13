use serde::{Deserialize, Serialize};

use crate::{event::EventMessage, prefix::SelfAddressingPrefix};

use super::key_state_notice::KeyStateNotice;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ReplyData {
    #[serde(rename = "d")]
    pub digest: Option<SelfAddressingPrefix>,
    #[serde(rename = "a")]
    pub data: EventMessage<KeyStateNotice>,
}
