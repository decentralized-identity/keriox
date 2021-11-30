use serde::{Deserialize, Serialize};

use crate::{event::EventMessage, prefix::SelfAddressingPrefix};

use super::key_state_notice::KeyStateNotice;

// {
//   "v" : "KERI10JSON00011c_",  
//   "t" : "rpy",  
//   "d" : "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM", 
//   "dt": "2020-08-22T17:50:12.988921+00:00",
//   "r" : "logs/processor",
//   "a" : 
//   {
//     "d":  "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
//     "i": "EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM",
//     "name": "John Jones",
//     "role": "Founder",
//   }
// }

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ReplyData {
	#[serde(rename = "d")]
    pub digest: SelfAddressingPrefix,
    #[serde(rename = "a")]
	pub data: EventMessage<KeyStateNotice>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Data {
	data: String,
}
