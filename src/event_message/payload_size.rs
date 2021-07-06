use serde::{Serialize, Deserialize};
use crate::error::Error;
use std::convert::TryFrom;

// Payload sizes pre unit
// according to:
// https://github.com/decentralized-identity/keri/blob/master/kids/kid0001.md#base64-master-code-table
#[derive(Serialize, Deserialize)]
pub(crate) enum PayloadType {
    A,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
    I,
    J,
    K,
    L,
    M,
    #[serde(rename = "0A")]
    OA,
    #[serde(rename = "0B")]
    OB,
    #[serde(rename = "0C")]
    OC,
    #[serde(rename = "0D")]
    OD,
    #[serde(rename = "0E")]
    OE,
    #[serde(rename = "0F")]
    OF,
    #[serde(rename = "0G")]
    OG,
    #[serde(rename = "0H")]
    OH,
    #[serde(rename = "1AAA")]
    IAAA,
    #[serde(rename = "1AAB")]
    IAAB,
    #[serde(rename = "1AAC")]
    IAAC,
    #[serde(rename = "1AAD")]
    IAAD,
    #[serde(rename = "1AAE")]
    IAAE,
    #[serde(rename = "1AAF")]
    IAAF,
    #[serde(rename = "1AAG")]
    IAAG,
    // TODO: Indexed signatures
}

impl PayloadType {
    pub(crate) fn size(&self) -> usize {
        match self {
            Self::A 
            | Self::B
            | Self::C
            | Self::D
            | Self::E
            | Self::F
            | Self::G
            | Self::H
            | Self::I
            | Self::J => 88,
            Self::K | Self::L => 76,
            Self::M => 4,
            Self::OA => 24,
            Self::OB
            | Self::OC
            | Self::OD
            | Self::OE
            | Self::OF
            | Self::OG => 88,
            Self::OH | Self::IAAF => 8,
            Self::IAAA | Self::IAAB => 48,
            Self::IAAC | Self::IAAD => 80,
            Self::IAAE => 156,
            Self::IAAG => 36,
        }
    }
}

impl TryFrom<&str> for PayloadType {
    type Error = Error;
    fn try_from(data: &str) -> Result<Self, Error> {
        match data {
           "A" => Ok(Self::A),
           "B" => Ok(Self::B),
           "C" => Ok(Self::C),
           "D" => Ok(Self::D),
           "E" => Ok(Self::E),
           "F" => Ok(Self::F),
           "G" => Ok(Self::G),
           "H" => Ok(Self::H),
           "I" => Ok(Self::I),
           "J" => Ok(Self::J),
           "K" => Ok(Self::K),
           "L" => Ok(Self::L),
           "M" => Ok(Self::M),
           "0A" => Ok(Self::OA),
           "0B" => Ok(Self::OB),
           "0C" => Ok(Self::OC),
           "0D" => Ok(Self::OD),
           "0E" => Ok(Self::OE),
           "0F" => Ok(Self::OF),
           "0G" => Ok(Self::OG),
           "0H" => Ok(Self::OH),
           "1AAA" => Ok(Self::IAAA),
           "1AAB" => Ok(Self::IAAB),
           "1AAC" => Ok(Self::IAAC),
           "1AAD" => Ok(Self::IAAD),
           "1AAE" => Ok(Self::IAAE),
           "1AAF" => Ok(Self::IAAF),
           "1AAG" => Ok(Self::IAAG),
           _ => Err(Error::ImproperPrefixType)
       }
    }
}
