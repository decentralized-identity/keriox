use super::Prefix;
use crate::{
    error::Error,
    keys::{PrivateKey, PublicKey},
};
use base64::decode_config;
use core::str::FromStr;
use ed25519_dalek::SecretKey;
use k256::ecdsa::{SigningKey, VerifyingKey};

#[derive(Debug, PartialEq, Clone)]
pub enum SeedPrefix {
    RandomSeed128(Vec<u8>),
    RandomSeed256Ed25519(Vec<u8>),
    RandomSeed256ECDSAsecp256k1(Vec<u8>),
    RandomSeed448(Vec<u8>),
}

impl SeedPrefix {
    pub fn derive_key_pair(&self) -> Result<(PublicKey, PrivateKey), Error> {
        match self {
            Self::RandomSeed256Ed25519(seed) => {
                let secret = SecretKey::from_bytes(seed)?;
                let vk =
                    PublicKey::new(ed25519_dalek::PublicKey::from(&secret).as_bytes().to_vec());
                let sk = PrivateKey::new(secret.as_bytes().to_vec());
                Ok((vk, sk))
            }
            Self::RandomSeed256ECDSAsecp256k1(seed) => {
                let sk = SigningKey::from_bytes(seed)?;
                Ok((
                    PublicKey::new(VerifyingKey::from(&sk).to_bytes().to_vec()),
                    PrivateKey::new(sk.to_bytes().to_vec()),
                ))
            }
            _ => Err(Error::ImproperPrefixType),
        }
    }
}

impl FromStr for SeedPrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..1] {
            "A" => Ok(Self::RandomSeed256Ed25519(decode_config(
                &s[1..],
                base64::URL_SAFE,
            )?)),
            "J" => Ok(Self::RandomSeed256ECDSAsecp256k1(decode_config(
                &s[1..],
                base64::URL_SAFE,
            )?)),
            "K" => Ok(Self::RandomSeed448(decode_config(
                &s[1..],
                base64::URL_SAFE,
            )?)),
            "0" => match &s[1..2] {
                "A" => Ok(Self::RandomSeed128(decode_config(
                    &s[2..],
                    base64::URL_SAFE,
                )?)),
                _ => Err(Error::DeserializeError(format!(
                    "Unknown seed prefix cod: {}",
                    s
                ))),
            },
            _ => Err(Error::DeserializeError(format!(
                "Unknown seed prefix cod: {}",
                s
            ))),
        }
    }
}

impl Prefix for SeedPrefix {
    fn derivative(&self) -> Vec<u8> {
        match self {
            Self::RandomSeed256Ed25519(seed) => seed.to_owned(),
            Self::RandomSeed256ECDSAsecp256k1(seed) => seed.to_owned(),
            Self::RandomSeed448(seed) => seed.to_owned(),
            Self::RandomSeed128(seed) => seed.to_owned(),
        }
    }
    fn derivation_code(&self) -> String {
        match self {
            Self::RandomSeed256Ed25519(_) => "A".to_string(),
            Self::RandomSeed256ECDSAsecp256k1(_) => "J".to_string(),
            Self::RandomSeed448(_) => "K".to_string(),
            Self::RandomSeed128(_) => "0A".to_string(),
        }
    }
}

#[test]
fn test_derive_keypair() -> Result<(), Error> {
    use base64::URL_SAFE;

    // taken from KERIPY: tests/core/test_eventing.py#1512
    let seeds = vec![
        "ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc",
        "A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q",
        "AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y",
        "Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8",
        "A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E",
        "AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc",
        "AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw",
        "ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY",
    ];

    let expected_pubkeys = vec![
        "SuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA=",
        "VcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI=",
        "T1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8=",
        "KPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ=",
        "1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU=",
        "4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM=",
        "VjWcaNX2gCkHOjk6rkmqPBCxkRCqwIJ-3OjdYmMwxf4=",
        "T1nEDepd6CSAMCE7NY_jlLdG6_mKUlKS_mW-2HJY1hg=",
    ];

    for (seed_str, expected_pk) in seeds.iter().zip(expected_pubkeys.iter()) {
        let seed: SeedPrefix = seed_str.parse()?;
        let (pub_key, _priv_key) = seed.derive_key_pair()?;
        let b64_pubkey = base64::encode_config(pub_key.key(), URL_SAFE);
        assert_eq!(&b64_pubkey, expected_pk);
    }

    Ok(())
}
