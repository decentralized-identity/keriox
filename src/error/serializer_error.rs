use std;
use std::fmt::{self, Display};

use serde::{de, ser};

pub type Result<T> = std::result::Result<T, Error>;

// This is a bare-bones implementation. A real library would provide additional
// information in its error type, for example the line and column at which the
// error occurred, the byte offset into the input, or the current key being
// processed.
#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    // One or more variants that can be created by data structures through the
    // `ser::Error` and `de::Error` traits. For example the Serialize impl for
    // Mutex<T> might return an error because the mutex is poisoned, or the
    // Deserialize impl for a struct may return an error because a required
    // field is missing.
    Message(String),

    // Zero or more variants that can be created directly by the Serializer and
    // Deserializer without going through `ser::Error` and `de::Error`. These
    // are specific to the format, in this case JSON.
    Eof,
    Syntax,
    ExpectedBoolean,
    ExpectedInteger,
    ExpectedString,
    ExpectedNull,
    ExpectedArray,
    ExpectedArrayComma,
    ExpectedArrayEnd,
    ExpectedMap,
    ExpectedMapColon,
    ExpectedMapComma,
    ExpectedMapEnd,
    ExpectedEnum,
    TrailingCharacters,
}

impl ser::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl de::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Message(msg) => formatter.write_str(msg),
            Error::Eof => formatter.write_str("unexpected end of input"),
            Error::Syntax => formatter.write_str("incorrect syntax"),
            Error::ExpectedBoolean => formatter.write_str("incorrect input: expected boolean"),
            Error::ExpectedInteger => formatter.write_str("incorrect input: expected integer"),
            Error::ExpectedString => formatter.write_str("incorrect input: expected string"),
            Error::ExpectedNull => formatter.write_str("incorrect input: expected null"),
            Error::ExpectedArray => formatter.write_str("incorrect input: expected array"),
            Error::ExpectedArrayComma => {
                formatter.write_str("incorrect input: expected array comma")
            }
            Error::ExpectedArrayEnd => formatter.write_str("incorrect input: expected array end"),
            Error::ExpectedMap => formatter.write_str("incorrect input: expected map"),
            Error::ExpectedMapColon => formatter.write_str("incorrect input: expected map colon"),
            Error::ExpectedMapComma => formatter.write_str("incorrect input: expected map comma"),
            Error::ExpectedMapEnd => formatter.write_str("incorrect input: expected map end"),
            Error::ExpectedEnum => formatter.write_str("incorrect input: expected enum"),
            Error::TrailingCharacters => {
                formatter.write_str("incorrect input: unexpected trailing characters")
            }
        }
    }
}

impl std::error::Error for Error {}
