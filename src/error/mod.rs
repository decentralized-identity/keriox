use base64::DecodeError;
use core::num::ParseIntError;
use ed25519_dalek;
use rmp_serde as serde_mgpk;
use serde_cbor;
use serde_json;
use thiserror::Error;

pub mod serializer_error;

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

    #[error("Event signature verification faulty")]
    FaultySignatureVerification,

    #[error("Error while applying event: out of order event")]
    EventOutOfOrderError,

    #[error("Error while applying event: duplicate event")]
    EventDuplicateError,

    #[error("Not enough signatures while verifying")]
    NotEnoughSigsError,

    #[error("Signature verification failed")]
    SignatureVerificationError,

    #[error("Deserialize error: {0}")]
    DeserializeError(String),

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

    #[error("Invalid identifier state")]
    InvalidIdentifierStat,

    #[cfg(feature = "async")]
    #[error("Zero send error")]
    ZeroSendError,

    #[error("Failed to obtain mutable ref to Ark of KeyManager")]
    MutArcKeyVaultError,

    #[error(transparent)]
    Ed25519DalekSignatureError(#[from] ed25519_dalek::SignatureError),

    #[error(transparent)]
    SledError(#[from] sled::Error),

    #[error(transparent)]
    SerdeSerError(#[from] serializer_error::Error),

    #[cfg(feature = "wallet")]
    #[error(transparent)]
    WalletError(#[from] universal_wallet::Error),

    #[error("mutex is poisoned")]
    MutexPoisoned,

    #[error("Incorrect event digest")]
    IncorrectDigest,

    #[cfg(feature = "query")]
    #[error(transparent)]
    QueryError(#[from] crate::query::QueryError),

    #[error("Public Key Error: {0}")]
    PublicKeyError(String),
}

impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        Error::MutexPoisoned
    }
}
