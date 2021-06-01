use base64::DecodeError;
use core::num::ParseIntError;
use ed25519_dalek;
use rmp_serde as serde_mgpk;
use serde_cbor;
use serde_json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error during Serialization: {0}")]
    SerializationError(String),

    #[error("JSON Serialization error")]
    JSONSerializationError {
        #[from]
        source: serde_json::Error,
    },

    #[error("CBOR Serialization error")]
    CBORSerializationError {
        #[from]
        source: serde_cbor::Error,
    },

    #[error("MessagePack Serialization error")]
    MsgPackSerializationError {
        #[from]
        source: serde_mgpk::encode::Error,
    },

    #[error("Error parsing numerical value: {source}")]
    IntegerParseValue {
        #[from]
        source: ParseIntError,
    },

    #[error("Error while applying event: {0}")]
    SemanticError(String),

    #[error("Error while applying event: out of order event")]
    EventOutOfOrderError,

    #[error("No event of given sn and prefix in database")]
    NoEventError,

    #[error("Error while aplying event: duplicate event")]
    EventDuplicateError,

    #[error("Not enough signatures while verifing")]
    NotEnoughSigsError,

    #[error("Deserialization error")]
    DeserializationError,

    #[error("Identifier is not indexed into the DB")]
    NotIndexedError,

    #[error("Identifier ID is already present in the DB")]
    IdentifierPresentError,

    #[error("Base64 Decoding error")]
    Base64DecodingError {
        #[from]
        source: DecodeError,
    },

    #[error("Improper Prefix Type")]
    ImproperPrefixType,

    #[error("Storage error")]
    StorageError,

    #[error(transparent)]
    Ed25519DalekSignatureError(#[from] ed25519_dalek::SignatureError),

    #[error(transparent)]
    SledError(#[from] sled::Error),
}
