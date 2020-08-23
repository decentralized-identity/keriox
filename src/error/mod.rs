use base64::DecodeError;
use serde::de;
use thiserror::Error;
use ursa::CryptoError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error during Serialization: {0}")]
    SerializationError(String),

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
