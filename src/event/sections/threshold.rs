use fraction::Fraction;

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(untagged)]
pub enum SignatureThreshold {
    #[serde(with = "SerHex::<Compact>")]
    Simple(u64),
    Weighted(Vec<Fraction>)
}
