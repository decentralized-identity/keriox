use crate::prefix::Prefix;
use serde::{Deserialize, Serialize};
pub mod event_data;
pub mod sections;

use self::event_data::EventData;

#[derive(Serialize, Deserialize)]
pub struct Event {
    #[serde(rename(serialize = "id", deserialize = "id"))]
    pub prefix: Prefix,

    pub sn: u64,

    #[serde(flatten)]
    pub event_data: EventData,
}
