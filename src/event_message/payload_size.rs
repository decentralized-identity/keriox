use crate::error::Error;
use base64::encode_config;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt::Display};

// Payload sizes pre unit
// according to:
// https://github.com/decentralized-identity/keri/blob/master/kids/kid0001.md#base64-master-code-table
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum PayloadType {
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
    // Count of attached qualified Base64 indexed controller signatures
    #[serde(rename = "-A")]
    MA,
    // Count of attached qualified Base64 indexed witness signatures
    #[serde(rename = "-B")]
    MB,
    // Count of attached qualified Base64 nontransferable identifier receipt
    // couples pre+sig
    #[serde(rename = "-C")]
    MC,
    #[serde(rename = "-D")]
    MD,
    #[serde(rename = "-E")]
    ME,
    // Count of attached qualified Base64 transferable indexed sig groups
    // pre+snu+dig + idx sig group
    #[serde(rename = "-F")]
    MF,
    #[serde(rename = "-G")]
    MG,
    #[serde(rename = "-U")]
    MU,
    #[serde(rename = "-V")]
    MV,
    #[serde(rename = "-W")]
    MW,
    #[serde(rename = "-X")]
    MX,
    #[serde(rename = "-Y")]
    MY,
    #[serde(rename = "-Z")]
    MZ,
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
            | Self::J => 44,
            Self::K | Self::L => 76,
            Self::M => 4,
            Self::OA => 24,
            Self::OB | Self::OC | Self::OD | Self::OE | Self::OF | Self::OG => 88,
            Self::OH | Self::IAAF => 8,
            Self::IAAA | Self::IAAB => 48,
            Self::IAAC | Self::IAAD => 80,
            Self::IAAE => 156,
            Self::IAAG => 36,
            Self::MA | Self::MB => 88,
            _ => 0, // TODO: fill proper sizes
        }
    }

    pub(crate) fn master_code_size(&self, qb2: bool) -> usize {
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
            | Self::J
            | Self::K
            | Self::L
            | Self::M => 1,
            Self::OA | Self::OB | Self::OC | Self::OD | Self::OE | Self::OF | Self::OH => 2,
            Self::MA
            | Self::MB
            | Self::MC
            | Self::MD
            | Self::ME
            | Self::MF
            | Self::MG
            | Self::MU
            | Self::MV
            | Self::MW
            | Self::MX
            | Self::MY
            | Self::MZ => {
                if qb2 {
                    3
                } else {
                    4
                }
            }
            _ => 0,
        }
    }

    // Return size of adjustable part of master codes, respesented as "#" in
    // code table.
    pub(crate) fn index_length(&self) -> usize {
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
            | Self::J
            | Self::K
            | Self::L
            | Self::M => 0,
            Self::OA | Self::OB | Self::OC | Self::OD | Self::OE | Self::OF | Self::OH => 0,
            Self::MA
            | Self::MB
            | Self::MC
            | Self::MD
            | Self::ME
            | Self::MF
            | Self::MG
            | Self::MU
            | Self::MV
            | Self::MW
            | Self::MX
            | Self::MY
            | Self::MZ => 2,
            _ => todo!(),
        }
    }

    pub fn adjust_with_num(&self, sn: u16) -> String {
        let expected_length = self.index_length();
        if expected_length > 0 {
            let i = num_to_b64(sn);
            if i.len() < expected_length {
                // refill string to have proper size
                let missing_part = "A".repeat(expected_length - i.len());
                [self.to_string(), missing_part, i].join("")
            } else {
                [self.to_string(), i].join("")
            }
        } else {
            self.to_string()
        }
    }
}

pub fn num_to_b64(num: u16) -> String {
    match num {
        n if n < 63 => {
            encode_config([num.to_be_bytes()[1] << 2], base64::URL_SAFE_NO_PAD)[..1].to_string()
        }
        n if n < 4095 => encode_config(num.to_be_bytes(), base64::URL_SAFE_NO_PAD)[..2].to_string(),
        _ => encode_config(num.to_be_bytes(), base64::URL_SAFE_NO_PAD),
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
            "-A" => Ok(Self::MA),
            "-B" => Ok(Self::MB),
            "-C" => Ok(Self::MC),
            "-D" => Ok(Self::MD),
            "-E" => Ok(Self::ME),
            "-F" => Ok(Self::MF),
            "-U" => Ok(Self::MU),
            "-V" => Ok(Self::MV),
            "-W" => Ok(Self::MW),
            "-X" => Ok(Self::MX),
            "-Y" => Ok(Self::MY),
            "-Z" => Ok(Self::MZ),
            _ => Err(Error::ImproperPrefixType),
        }
    }
}

impl Display for PayloadType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A => f.write_str("A"),
            Self::B => f.write_str("B"),
            Self::C => f.write_str("C"),
            Self::D => f.write_str("D"),
            Self::E => f.write_str("D"),
            Self::F => f.write_str("F"),
            Self::G => f.write_str("G"),
            Self::H => f.write_str("H"),
            Self::I => f.write_str("I"),
            Self::J => f.write_str("J"),
            Self::K => f.write_str("K"),
            Self::L => f.write_str("L"),
            Self::M => f.write_str("M"),
            Self::OA => f.write_str("0A"),
            Self::OB => f.write_str("0B"),
            Self::OC => f.write_str("0C"),
            Self::OD => f.write_str("0D"),
            Self::OE => f.write_str("0E"),
            Self::OF => f.write_str("0F"),
            Self::OG => f.write_str("0G"),
            Self::OH => f.write_str("0H"),
            Self::IAAA => f.write_str("1AAA"),
            Self::IAAB => f.write_str("1AAB"),
            Self::IAAC => f.write_str("1AAC"),
            Self::IAAD => f.write_str("1AAD"),
            Self::IAAE => f.write_str("1AAE"),
            Self::IAAF => f.write_str("1AAF"),
            Self::IAAG => f.write_str("1AAG"),
            Self::MA => f.write_str("-A"),
            Self::MB => f.write_str("-B"),
            Self::MC => f.write_str("-C"),
            Self::MD => f.write_str("-D"),
            Self::ME => f.write_str("-E"),
            Self::MF => f.write_str("-F"),
            Self::MG => f.write_str("-G"),
            Self::MU => f.write_str("-U"),
            Self::MV => f.write_str("-V"),
            Self::MW => f.write_str("-W"),
            Self::MX => f.write_str("-X"),
            Self::MY => f.write_str("-Y"),
            Self::MZ => f.write_str("-Z"),
        }
    }
}

#[test]
fn num_to_b64_test() {
    assert_eq!("A", num_to_b64(0));
    assert_eq!("B", num_to_b64(1));
    assert_eq!("C", num_to_b64(2));
    assert_eq!("D", num_to_b64(3));
    assert_eq!("b", num_to_b64(27));
    assert_eq!("AE", num_to_b64(64));
}

#[test]
fn test_adjust_with_num() {
    assert_eq!(PayloadType::MA.adjust_with_num(2), "-AAC");
    assert_eq!(PayloadType::MA.adjust_with_num(27), "-AAb");
}
