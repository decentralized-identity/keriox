use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error during Serialization: {0}")]
    SerializationError(String),

    #[error("Error while applying event: {0}")]
    SemanticError(String),
}
