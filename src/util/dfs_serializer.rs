use serde::{ser, Serialize};
use std::{fmt, io};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error during Serialization: {source}")]
    SerializationError {
        #[from]
        source: io::Error,
    },

    #[error("Error Converting to String: {source}")]
    StringRepresentationError {
        #[from]
        source: std::string::FromUtf8Error,
    },

    #[error("Unexpected Error: {0}")]
    Custom(String),
}

fn io2ce(io: io::Error) -> Error {
    io.into()
}

pub struct Serializer<W> {
    // This string starts empty and data is appended as values are serialized.
    writer: W,
}

impl<W> Serializer<W>
where
    W: io::Write,
{
    pub fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl ser::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Error::Custom(msg.to_string())
    }
}

// By convention, the public API of a Serde serializer is one or more `to_abc`
// functions such as `to_string`, `to_bytes`, or `to_writer` depending on what
// Rust types the serializer is able to produce as output.
pub fn to_string<T>(value: &T) -> Result<String, Error>
where
    T: Serialize,
{
    let vec = to_vec(value)?;
    let string = String::from_utf8(vec)?;
    Ok(string)
}

pub fn to_writer<W, T>(writer: W, value: &T) -> Result<(), Error>
where
    W: io::Write,
    T: ?Sized + Serialize,
{
    let mut ser = Serializer::new(writer);
    value.serialize(&mut ser)?;
    Ok(())
}

pub fn to_vec<T>(value: &T) -> Result<Vec<u8>, Error>
where
    T: ?Sized + Serialize,
{
    let mut writer = Vec::with_capacity(128);
    to_writer(&mut writer, value)?;
    Ok(writer)
}

impl<'a, W> ser::Serializer for &'a mut Serializer<W>
where
    W: io::Write,
{
    // The output type produced by this `DepthFirstSerializer` during successful serialization.
    type Ok = ();

    // The error type when some error occurs during serialization.
    type Error = Error;

    // Associated types for keeping track of additional state while serializing
    // compound data structures like sequences and maps. In this case no
    // additional state is required beyond what is already stored in the
    // DepthFirstSerializer struct.
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    // TODO booleans do not appear in the KERI event data model, how should they be represented?
    fn serialize_bool(self, v: bool) -> Result<(), Self::Error> {
        self.writer
            .write_all(if v { b"true" } else { b"false" })
            .map_err(io2ce)
    }

    // TODO encode all integers as 64 bit?
    fn serialize_i8(self, v: i8) -> Result<(), Self::Error> {
        let mut buffer = itoa::Buffer::new();
        let s = buffer.format(v);
        self.writer.write_all(s.as_bytes()).map_err(io2ce)
    }

    fn serialize_i16(self, v: i16) -> Result<(), Self::Error> {
        let mut buffer = itoa::Buffer::new();
        let s = buffer.format(v);
        self.writer.write_all(s.as_bytes()).map_err(io2ce)
    }

    fn serialize_i32(self, v: i32) -> Result<(), Self::Error> {
        let mut buffer = itoa::Buffer::new();
        let s = buffer.format(v);
        self.writer.write_all(s.as_bytes()).map_err(io2ce)
    }

    fn serialize_i64(self, v: i64) -> Result<(), Self::Error> {
        let mut buffer = itoa::Buffer::new();
        let s = buffer.format(v);
        self.writer.write_all(s.as_bytes()).map_err(io2ce)
    }

    fn serialize_u8(self, v: u8) -> Result<(), Self::Error> {
        let mut buffer = itoa::Buffer::new();
        let s = buffer.format(v);
        self.writer.write_all(s.as_bytes()).map_err(io2ce)
    }

    fn serialize_u16(self, v: u16) -> Result<(), Self::Error> {
        let mut buffer = itoa::Buffer::new();
        let s = buffer.format(v);
        self.writer.write_all(s.as_bytes()).map_err(io2ce)
    }

    fn serialize_u32(self, v: u32) -> Result<(), Self::Error> {
        let mut buffer = itoa::Buffer::new();
        let s = buffer.format(v);
        self.writer.write_all(s.as_bytes()).map_err(io2ce)
    }

    fn serialize_u64(self, v: u64) -> Result<(), Self::Error> {
        let mut buffer = itoa::Buffer::new();
        let s = buffer.format(v);
        self.writer.write_all(s.as_bytes()).map_err(io2ce)
    }

    fn serialize_f32(self, v: f32) -> Result<(), Self::Error> {
        let mut buffer = ryu::Buffer::new();
        let s = buffer.format_finite(v);
        self.writer.write_all(s.as_bytes()).map_err(io2ce)
    }

    fn serialize_f64(self, v: f64) -> Result<(), Self::Error> {
        let mut buffer = ryu::Buffer::new();
        let s = buffer.format_finite(v);
        self.writer.write_all(s.as_bytes()).map_err(io2ce)
    }

    fn serialize_char(self, v: char) -> Result<(), Self::Error> {
        self.writer
            .write_all(&v.to_string().as_bytes())
            .map_err(io2ce)
    }

    fn serialize_str(self, v: &str) -> Result<(), Self::Error> {
        self.writer.write_all(&v.as_bytes()).map_err(io2ce)
    }

    // Serialize a byte array as an array of bytes. Could also use a base64
    // string here. Binary formats will typically represent byte arrays more
    // compactly.
    fn serialize_bytes(self, v: &[u8]) -> Result<(), Self::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = self.serialize_seq(Some(v.len()))?;
        for byte in v {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }

    // An absent optional is omitted
    fn serialize_none(self) -> Result<(), Self::Error> {
        Ok(())
    }

    // A present optional is represented as just the contained value. Note that
    // this is a lossy representation. For example the values `Some(())` and
    // `None` both are ommitted in the serialized output.
    fn serialize_some<T>(self, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    // In Serde, unit means an anonymous value containing no data. Omit this too
    fn serialize_unit(self) -> Result<(), Self::Error> {
        Ok(())
    }

    // Unit struct means a named value containing no data. Again, since there is
    // no data, map this to JSON as `null`. There is no need to serialize the
    // name in most formats.
    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), Self::Error> {
        self.serialize_unit()
    }

    // When serializing a unit variant (or any other kind of variant), formats
    // can choose whether to keep track of it by index or by name. Binary
    // formats typically use the index of the variant and human-readable formats
    // typically use the name.
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<(), Self::Error> {
        self.serialize_str(variant)
    }

    // As is done here, serializers are encouraged to treat newtype structs as
    // insignificant wrappers around the data they contain.
    fn serialize_newtype_struct<T>(self, _name: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    // Note that newtype variant (and all of the other variant serialization
    // methods) refer exclusively to the "externally tagged" enum
    // representation.
    //
    // Serialize this to just the value
    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut *self)?;
        Ok(())
    }

    // Now we get to the serialization of compound types.
    //
    // The start of the sequence, each value, and the end are three separate
    // method calls. This one is responsible only for serializing the start.
    //
    // In depth first value serialization, sequences are flattened to a concatted value.
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(self)
    }

    // Tuples are treated the same as sequences
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.serialize_seq(Some(len))
    }

    // Tuple structs look just like sequences.
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.serialize_seq(Some(len))
    }

    // Tuple variants are represented in just the data
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Ok(self)
    }

    // Maps are represented in DFS as concatted values
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Ok(self)
    }

    // Structs look just like maps and sequences in DFS
    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        self.serialize_map(Some(len))
    }

    // Struct variants are represented in DFS as flattened and concatted values
    // This is the externally tagged representation.
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Ok(self)
    }
}

// The following 7 impls deal with the serialization of compound types like
// sequences and maps. Serialization of such types is begun by a DepthFirstSerializer
// method and followed by zero or more calls to serialize individual elements of
// the compound type and one call to end the compound type.
//
// This impl is SerializeSeq so these methods are called after `serialize_seq`
// is called on the DepthFirstSerializer.
impl<'a, W> ser::SerializeSeq for &'a mut Serializer<W>
where
    W: io::Write,
{
    // Must match the `Ok` type of the serializer.
    type Ok = ();
    // Must match the `Error` type of the serializer.
    type Error = Error;

    // Serialize a single element of the sequence.
    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    // Close the sequence.
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

// Same thing but for tuples.
impl<'a, W> ser::SerializeTuple for &'a mut Serializer<W>
where
    W: io::Write,
{
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

// Same thing but for tuple structs.
impl<'a, W> ser::SerializeTupleStruct for &'a mut Serializer<W>
where
    W: io::Write,
{
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

// Tuple variants
impl<'a, W> ser::SerializeTupleVariant for &'a mut Serializer<W>
where
    W: io::Write,
{
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

// Some `Serialize` types are not able to hold a key and value in memory at the
// same time so `SerializeMap` implementations are required to support
// `serialize_key` and `serialize_value` individually.
//
// There is a third optional method on the `SerializeMap` trait. The
// `serialize_entry` method allows serializers to optimize for the case where
// key and value are both available simultaneously.
impl<'a, W> ser::SerializeMap for &'a mut Serializer<W>
where
    W: io::Write,
{
    type Ok = ();
    type Error = Error;

    // The Serde data model allows map keys to be any serializable type. DFS does not
    // need to serialize the keys anyway
    fn serialize_key<T>(&mut self, _key: &T) -> Result<(), Error>
    where
        T: ?Sized + Serialize,
    {
        Ok(())
    }

    fn serialize_value<T>(&mut self, value: &T) -> Result<(), Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

// Structs are like maps in which the keys are constrained to be compile-time
// constant strings.
impl<'a, W> ser::SerializeStruct for &'a mut Serializer<W>
where
    W: io::Write,
{
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<(), Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

// Similar to `SerializeTupleVariant`
impl<'a, W> ser::SerializeStructVariant for &'a mut Serializer<W>
where
    W: io::Write,
{
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<(), Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::to_string;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Simple {
        str: String,
        tuple: (u32, u32, String),
    }
    #[derive(Serialize)]
    struct Nested {
        int: u32,
        seq: Vec<&'static str>,
        nested: Simple,
    }

    #[derive(Serialize)]
    enum E {
        Unit,
        Newtype(u32),
        Tuple(u32, u32),
        Struct { a: u32, b: String },
    }

    #[derive(Serialize)]
    struct NewType(E);

    #[derive(Serialize)]
    struct Complex {
        tuple: (E, String, Vec<Simple>),
        en: E,
        list: Vec<Nested>,
        nt: NewType,
    }

    #[test]
    fn test_struct0() {
        let test = Nested {
            int: 1,
            seq: vec!["a", "b"],
            nested: Simple {
                str: "Hello".to_string(),
                tuple: (1, 5, "goodbye".to_string()),
            },
        };
        let expected = r#"1abHello15goodbye"#;
        assert_eq!(to_string(&test).unwrap(), expected);
    }

    #[test]
    fn test_struct1() {
        let test = Complex {
            tuple: (
                E::Unit,
                "a String".to_string(),
                vec![
                    Simple {
                        str: "another String".to_string(),
                        tuple: (0, 2, "lol".to_string()),
                    },
                    Simple {
                        str: "getting tiresome".to_string(),
                        tuple: (4, 4389749, "___@-".to_string()),
                    },
                ],
            ),
            en: E::Struct {
                a: 500,
                b: "b,".to_string(),
            },
            list: vec![
                Nested {
                    int: 1,
                    seq: vec!["a", "b", "c", "e"],
                    nested: Simple {
                        str: "Hello".to_string(),
                        tuple: (1, 5, "goodbye".to_string()),
                    },
                },
                Nested {
                    int: 100,
                    seq: vec!["a2", "b3"],
                    nested: Simple {
                        str: "He".to_string(),
                        tuple: (345, 531213, "foo".to_string()),
                    },
                },
            ],
            nt: NewType(E::Tuple(200, 300)),
        };
        let expected = r#"Unita Stringanother String02lolgetting tiresome44389749___@-500b,1abceHello15goodbye100a2b3He345531213foo200300"#;
        assert_eq!(to_string(&test).unwrap(), expected);
    }

    #[test]
    fn test_enum() {
        let u = E::Unit;
        let expected = r#"Unit"#;
        assert_eq!(to_string(&u).unwrap(), expected);

        let n = E::Newtype(1);
        let expected = r#"1"#;
        assert_eq!(to_string(&n).unwrap(), expected);

        let t = E::Tuple(1, 2);
        let expected = r#"12"#;
        assert_eq!(to_string(&t).unwrap(), expected);

        let s = E::Struct {
            a: 1,
            b: "thing".to_string(),
        };
        let expected = r#"1thing"#;
        assert_eq!(to_string(&s).unwrap(), expected);
    }
}
