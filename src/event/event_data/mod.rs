pub mod delegated;
pub mod inception;
pub mod interaction;
pub mod receipt;
pub mod rotation;

use crate::{
    derivation::{self_addressing::SelfAddressing, DerivationCode},
    error::Error,
    event_message::serialization_info::{SerializationFormats, SerializationInfo},
    prefix::IdentifierPrefix,
    state::{EventSemantics, IdentifierState},
};
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};

pub use self::{
    delegated::{DelegatedInceptionEvent, DelegatedRotationEvent},
    inception::InceptionEvent,
    interaction::InteractionEvent,
    receipt::{ReceiptNonTransferable, ReceiptTransferable},
    rotation::RotationEvent,
};

/// Event Data
///
/// Event Data conveys the semantic content of a KERI event.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum EventData {
    Icp(InceptionEvent),
    Rot(RotationEvent),
    Ixn(InteractionEvent),
    Dip(DelegatedInceptionEvent),
    Drt(DelegatedRotationEvent),
    Rct(ReceiptNonTransferable),
    Vrc(ReceiptTransferable),
}

impl EventSemantics for EventData {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        match self {
            Self::Icp(e) => e.apply_to(state),
            Self::Rot(e) => e.apply_to(state),
            Self::Ixn(e) => e.apply_to(state),
            Self::Dip(e) => e.apply_to(state),
            Self::Drt(e) => e.apply_to(state),
            Self::Rct(e) => e.apply_to(state),
            Self::Vrc(e) => e.apply_to(state),
        }
    }
}

/// Dummy Event
///
/// Used only to encapsulate the prefix derivation process for inception and delegated inception
#[derive(Serialize, Debug, Clone)]
pub(crate) struct DummyEvent {
    #[serde(rename = "v")]
    serialization_info: SerializationInfo,
    #[serde(rename = "i")]
    prefix: String,
    #[serde(rename = "s", with = "SerHex::<Compact>")]
    sn: u8,
    #[serde(flatten)]
    data: EventData,
}

impl DummyEvent {
    pub fn derive_inception_data(
        icp: InceptionEvent,
        derivation: SelfAddressing,
        format: SerializationFormats,
    ) -> Result<Vec<u8>, Error> {
        Self::derive_data(EventData::Icp(icp), derivation, format)
    }

    pub fn derive_delegated_inception_data(
        dip: DelegatedInceptionEvent,
        derivation: SelfAddressing,
        format: SerializationFormats,
    ) -> Result<Vec<u8>, Error> {
        Self::derive_data(EventData::Dip(dip), derivation, format)
    }

    fn derive_data(
        data: EventData,
        derivation: SelfAddressing,
        format: SerializationFormats,
    ) -> Result<Vec<u8>, Error> {
        Ok(Self {
            serialization_info: SerializationInfo::new(
                format,
                Self {
                    serialization_info: SerializationInfo::new(format, 0),
                    prefix: Self::dummy_prefix(derivation),
                    sn: 0,
                    data: data.clone(),
                }
                .serialize()?
                .len(),
            ),
            prefix: Self::dummy_prefix(derivation),
            sn: 0,
            data: data,
        }
        .serialize()?)
    }

    fn serialize(&self) -> Result<Vec<u8>, Error> {
        self.serialization_info.kind.encode(&self)
    }

    fn dummy_prefix(derivation: SelfAddressing) -> String {
        std::iter::repeat("#")
            .take(derivation.code_len() + derivation.derivative_b64_len())
            .collect::<String>()
    }
}
