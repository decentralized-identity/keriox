use base64::DecodeError;
use serde::de;
use serde_json;
use thiserror::Error;
use ursa::CryptoError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error during Serialization: {0}")]
    SerializationError(String),

    #[error("JSON Serialization error")]
    JSONSerializationError {
        #[from]
        source: serde_json::Error,
    },

    #[error("Error while applying event: {0}")]
    SemanticError(String),

    #[error("validation error")]
    CryptoError(CryptoError),

    #[error("Deserialization error")]
    DeserializationError,

    #[error("Base64 Decoding error")]
    Base64DecodingError {
        #[from]
        source: DecodeError,
    },

    #[error("Improper Prefix Type")]
    ImproperPrefixType,
}
