use crate::error::Error;
use crate::event_message::CommonEvent;
use crate::event_message::serialization_info::SerializationInfo;
use crate::prefix::IdentifierPrefix;
use crate::prefix::SelfAddressingPrefix;
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};

use super::EventMessage;
use super::SerializationFormats;


#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Receipt {
    // #[serde(rename = "v")]
    // serialization_info: SerializationInfo,

    // #[serde(rename = "t")]
    // event_type: String,

    /// Receipted Event Digest
    ///
    /// A Qualified Digest of the event which this receipt is made for
    /// (not the receipt message itself).
    #[serde(rename = "d", skip_serializing)]
    pub receipted_event_digest: SelfAddressingPrefix,

    /// Receipted Event identifier 
    #[serde(rename = "i")]
    pub prefix: IdentifierPrefix,

    /// Receipted Event sn 
    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64
}

impl Receipt {
    pub fn to_message(self, format: SerializationFormats) -> Result<EventMessage<Receipt>, Error> {
        let len = EventMessage {
                serialization_info: SerializationInfo::new(format, 0),
                event: self.clone(),
            }
            .serialize()?
            .len();

        Ok(EventMessage {
            serialization_info: SerializationInfo::new(format, len),
            event: self,
        })
    }
}
//     pub fn new(serialization: SerializationFormats, receipted_event_digest: SelfAddressingPrefix, sn: u64, prefix: IdentifierPrefix) -> Self {
//         let msg_len = Self { 
//                 serialization_info: SerializationInfo::new(serialization, 0), 
//                 event_type: "rct".to_string(), 
//                 receipted_event_digest: receipted_event_digest.clone(), 
//                 prefix:prefix.clone(), 
//                 sn 
//             }
//             .serialize().unwrap()
//             .len();
//         Self { serialization_info: SerializationInfo::new(serialization, msg_len), event_type: "rct".to_string(), receipted_event_digest, prefix, sn }
//     }

//     pub fn serialize(&self) -> Result<Vec<u8>, Error> {
//         self.serialization_info.kind.encode(self)
//     }
// }

// impl Serialize for Receipt {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer {
//         // Helper struct for adding `t` field to EventMessage serialization
//         let mut em = serializer.serialize_struct("Receipt", 4)?;
//         em.serialize_field("v", &self.serialization_info)?;
//         em.serialize_field("t", "rct")?;
//         em.serialize_field("d", &self.digest)?;
//         em.serialize_field("i", &self.prefix)?;
//         em.serialize_field("s", &self.sn)?;
//         em.end()
//     }
// }

// impl EventSemantics for Receipt {}
impl CommonEvent for Receipt {
    fn get_type(&self) -> Option<String> {
        Some("rct".to_string())
    }

    fn get_digest(&self) -> Option<SelfAddressingPrefix> {
        Some(self.receipted_event_digest.clone())
    }
}

// {
//   "v": "KERI10JSON00011c_",
//   "t": "rct",
//   "d": "DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM",
//   "i": "AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
//   "s": "1"
// }