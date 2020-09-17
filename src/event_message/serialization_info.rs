use crate::error::Error;
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy)]
pub enum SerializationFormats {
    JSON,
    MGPK,
    CBOR,
}

impl SerializationFormats {
    pub fn encode<T: Serialize>(&self, message: &T) -> Result<Vec<u8>, Error> {
        match self {
            Self::JSON => serde_json::to_vec(message).map_err(|e| e.into()),
            Self::CBOR => serde_cbor::to_vec(message).map_err(|e| e.into()),
            Self::MGPK => Err(Error::SerializationError(
                "MessagePack unimplemented".to_string(),
            )),
        }
    }

    pub fn to_str(&self) -> String {
        match self {
            Self::JSON => "JSON",
            Self::CBOR => "CBOR",
            Self::MGPK => "MGPK",
        }
        .to_string()
    }
}

impl FromStr for SerializationFormats {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "JSON" => Ok(SerializationFormats::JSON),
            "MGPK" => Ok(SerializationFormats::MGPK),
            "CBOR" => Ok(SerializationFormats::CBOR),
            _ => Err(Error::DeserializationError),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SerializationInfo {
    pub major_version: u8,
    pub minor_version: u8,
    pub size: usize,
    pub kind: SerializationFormats,
}

impl SerializationInfo {
    pub fn new(kind: &SerializationFormats, size: usize) -> Self {
        Self {
            major_version: 1,
            minor_version: 0,
            size,
            kind: *kind,
        }
    }
    pub fn to_str(&self) -> String {
        format!(
            "KERI{:x}{:x}{}{:06x}_",
            self.major_version,
            self.minor_version,
            self.kind.to_str(),
            self.size
        )
    }
}

impl FromStr for SerializationInfo {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..4] {
            "KERI" => Ok(Self {
                major_version: u8::from_str_radix(&s[4..5], 16)?,
                minor_version: u8::from_str_radix(&s[5..6], 16)?,
                kind: SerializationFormats::from_str(&s[6..10])?,
                size: u16::from_str_radix(&s[10..16], 16)? as usize,
            }),
            _ => Err(Error::DeserializationError),
        }
    }
}

/// Serde compatible Serialize
impl Serialize for SerializationInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deserialize
impl<'de> Deserialize<'de> for SerializationInfo {
    fn deserialize<D>(deserializer: D) -> Result<SerializationInfo, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        SerializationInfo::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Default for SerializationInfo {
    fn default() -> Self {
        Self {
            major_version: 1,
            minor_version: 0,
            size: 0,
            kind: SerializationFormats::JSON,
        }
    }
}

#[test]
fn basic_serialize() -> Result<(), Error> {
    let si = SerializationInfo::new(&SerializationFormats::JSON, 100);

    let version_string = si.to_str();
    assert_eq!("KERI10JSON000064_".to_string(), version_string);
    Ok(())
}

#[test]
fn basic_deserialize() -> Result<(), Error> {
    let si = SerializationInfo::from_str("KERIa4CBOR000123_")?;

    assert_eq!(si.kind, SerializationFormats::CBOR);
    assert_eq!(si.major_version, 10);
    assert_eq!(si.minor_version, 4);
    assert_eq!(si.size, 291);
    Ok(())
}
