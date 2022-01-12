use crate::{
    derivation::{self_addressing::SelfAddressing, DerivationCode},
    error::Error,
    event::{
        event_data::{DelegatedInceptionEvent, EventData, InceptionEvent},
        SerializationFormats,
    },
};

use super::serialization_info::SerializationInfo;
use serde::Serialize;
use serde_hex::{Compact, SerHex};

fn dummy_prefix(derivation: &SelfAddressing) -> String {
    std::iter::repeat("#")
        .take(derivation.code_len() + derivation.derivative_b64_len())
        .collect::<String>()
}

/// Dummy Inception Event
///
/// Used only to encapsulate the prefix derivation process for inception and delegated inception
#[derive(Serialize, Debug, Clone)]
pub(crate) struct DummyInceptionEvent {
    #[serde(rename = "v")]
    serialization_info: SerializationInfo,
    #[serde(rename = "d")]
    digest: String,
    #[serde(rename = "i")]
    prefix: String,
    #[serde(rename = "s", with = "SerHex::<Compact>")]
    sn: u8,
    #[serde(flatten)]
    data: EventData,
}

impl DummyInceptionEvent {
    pub fn dummy_inception_data(
        icp: InceptionEvent,
        derivation: &SelfAddressing,
        format: SerializationFormats,
    ) -> Result<Vec<u8>, Error> {
        DummyInceptionEvent::derive_data(EventData::Icp(icp), derivation, format)
    }

    pub fn dummy_delegated_inception_data(
        dip: DelegatedInceptionEvent,
        derivation: &SelfAddressing,
        format: SerializationFormats,
    ) -> Result<Vec<u8>, Error> {
        DummyInceptionEvent::derive_data(EventData::Dip(dip), derivation, format)
    }

    fn derive_data(
        data: EventData,
        derivation: &SelfAddressing,
        format: SerializationFormats,
    ) -> Result<Vec<u8>, Error> {
        Ok(Self {
            serialization_info: SerializationInfo::new(
                format,
                Self {
                    serialization_info: SerializationInfo::new(format, 0),
                    prefix: dummy_prefix(derivation),
                    digest: dummy_prefix(derivation),
                    sn: 0,
                    data: data.clone(),
                }
                .serialize()?
                .len(),
            ),
            digest: dummy_prefix(derivation),
            prefix: dummy_prefix(derivation),
            sn: 0,
            data: data,
        }
        .serialize()?)
    }

    fn serialize(&self) -> Result<Vec<u8>, Error> {
        self.serialization_info.kind.encode(&self)
    }
}

#[derive(Serialize, Debug, Clone)]
pub(crate) struct DummyEventMessage<T: Serialize> {
    #[serde(rename = "v")]
    pub serialization_info: SerializationInfo,
    #[serde(rename = "d")]
    digest: String,
    #[serde(flatten)]
    data: T,
}

impl<T: Serialize> DummyEventMessage<T> {
    pub fn dummy_event(
        event: T,
        format: SerializationFormats,
        derivation: &SelfAddressing,
    ) -> Result<Self, Error> {
        Ok(Self {
            serialization_info: Self::get_serialization_info(&event, format, derivation)?,
            data: event,
            digest: dummy_prefix(derivation),
        })
    }

    fn get_size(
        event: &T,
        format: SerializationFormats,
        derivation: &SelfAddressing,
    ) -> Result<usize, Error> {
        Ok(DummyEventMessage {
            serialization_info: SerializationInfo::new(format, 0),
            data: event.clone(),
            digest: dummy_prefix(derivation),
        }
        .serialize()?
        .len())
    }

    pub fn get_serialization_info(
        event: &T,
        format: SerializationFormats,
        derivation: &SelfAddressing,
    ) -> Result<SerializationInfo, Error> {
        Ok(SerializationInfo::new(
            format,
            Self::get_size(&event, format, derivation)?,
        ))
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        self.serialization_info.kind.encode(&self)
    }
}
