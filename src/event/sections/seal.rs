use crate::prefix::{IdentifierPrefix, SelfAddressingPrefix};
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Seal {
    Location(LocationSeal),
    Event(EventSeal),
    Digest(DigestSeal),
    Root(RootSeal),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DigestSeal {
    #[serde(rename = "dig")]
    pub dig: SelfAddressingPrefix,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RootSeal {
    #[serde(rename = "root")]
    pub tree_root: SelfAddressingPrefix,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EventSeal {
    #[serde(rename = "pre")]
    pub prefix: IdentifierPrefix,

    #[serde(rename = "dig")]
    pub event_digest: SelfAddressingPrefix,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocationSeal {
    #[serde(rename = "pre")]
    pub prefix: IdentifierPrefix,

    #[serde(with = "SerHex::<Compact>")]
    pub sn: u64,

    pub ilk: String,

    #[serde(rename = "dig")]
    pub prior_digest: SelfAddressingPrefix,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DelegatingEventSeal {
    #[serde(rename = "pre")]
    pub prefix: IdentifierPrefix,

    #[serde(rename = "dig")]
    pub commitment: SelfAddressingPrefix,
}

#[test]
fn test_seal_deserialization() {
  // Event seal
  let seal_str = r#"{"pre":"Ek7M173EvQZ6kLjyorCwZK4XWwyNcSi6u7lz5-M6MyFE","dig":"EeBPcw30IVCylYANEGOg3V8f4nBYMspEpqNaq2Y8_knw"}"#;
  let seal: Seal = serde_json::from_str(seal_str).unwrap();
  assert!(matches!(seal, Seal::Event(_)));
  assert_eq!(serde_json::to_string(&seal).unwrap(), seal_str);

  // Location seal
  let seal_str = r#"{"pre":"EXmV-FiCyD7U76DoXSQoHlG30hFLD2cuYWEQPp0mEu1U","sn":"1","ilk":"ixn","dig":"Ey-05xXgtfYvKyMGa-dladxUQyXv4JaPg-gaKuXLfceQ"}"#;
  let seal: Seal = serde_json::from_str(seal_str).unwrap();
  assert!(matches!(seal, Seal::Location(_)));
  assert_eq!(serde_json::to_string(&seal).unwrap(), seal_str);

  // Digest seal
  let seal_str = r#"{"dig":"Ey-05xXgtfYvKyMGa-dladxUQyXv4JaPg-gaKuXLfceQ"}"#;
  let seal: Seal = serde_json::from_str(seal_str).unwrap();
  assert!(matches!(seal, Seal::Digest(_)));
  assert_eq!(serde_json::to_string(&seal).unwrap(), seal_str);
}
