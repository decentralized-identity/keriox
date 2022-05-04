use crate::error::Error;
use arrayref::array_ref;
use serde::{de::DeserializeOwned, Serialize};
use std::marker::PhantomData;

/// Imitates collection table per key
///
pub struct SledEventTreeVec<T> {
    tree: sled::Tree,
    marker: PhantomData<T>,
}

impl<T> SledEventTreeVec<T> {
    /// Creates new table.
    ///
    pub fn new(tree: sled::Tree) -> Self {
        Self {
            tree,
            marker: PhantomData,
        }
    }
}

/// DB "Tables" functionality
///
impl<T> SledEventTreeVec<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Gets all elements for given `key` as Vec<T>
    ///
    pub fn get(&self, key: u64) -> Result<Option<Vec<T>>, Error> {
        if let Ok(Some(v)) = self.tree.get(key_bytes(key)) {
            let set: Vec<T> = serde_cbor::from_slice(&v)?;
            Ok(Some(set))
        } else {
            Ok(None)
        }
    }

    /// Overwrites or adds new key<->value into the tree
    ///
    pub fn put(&self, key: u64, value: Vec<T>) -> Result<(), Error> {
        self.tree
            .insert(key_bytes(key), serde_cbor::to_vec(&value)?)?;
        Ok(())
    }

    /// Pushes element to existing set of T
    /// or creates new one with single element
    ///
    pub fn push(&self, key: u64, value: T) -> Result<(), Error> {
        if let Ok(Some(mut set)) = self.get(key) {
            set.push(value);
            self.put(key, set)
        } else {
            self.put(key, vec![value])
        }
    }

    /// Removes value `value` if present.
    ///
    pub fn remove(&self, key: u64, value: &T) -> Result<(), Error>
    where
        T: PartialEq,
    {
        if let Ok(Some(mut set)) = self.get(key) {
            set.retain(|e| e != value);
            self.put(key, set)
        } else {
            Ok(())
        }
    }

    /// Appends one `Vec<T>` into DB present one
    /// or `put()`s it if not present as is.
    ///
    pub fn append(&self, key: u64, value: Vec<T>) -> Result<(), Error>
    where
        T: ToOwned + Clone,
    {
        if let Ok(Some(mut set)) = self.get(key) {
            let mut value = value;
            set.append(&mut value);
            Ok(())
        } else {
            self.put(key, value)
        }
    }

    /// check if `T` is present in `Vec<T>` in the DB
    ///
    pub fn contains_value(&self, value: &T) -> bool
    where
        T: PartialEq,
    {
        self.tree.iter().flatten().any(|(_k, v)| {
            serde_cbor::from_slice::<Vec<T>>(&v)
                .unwrap()
                .contains(value)
        })
    }

    /// iterate inner collection under same key
    ///
    pub fn iter_values(&self, key: u64) -> Option<impl DoubleEndedIterator<Item = T>> {
        if let Ok(Some(values)) = self.tree.get(key_bytes(key)) {
            Some(
                serde_cbor::from_slice::<Vec<T>>(&values)
                    .unwrap()
                    .into_iter(),
            )
        } else {
            None
        }
    }

    pub fn get_all(&self) -> Option<impl DoubleEndedIterator<Item = T>> {
        Some(
            self.tree
                .into_iter()
                .flatten()
                .flat_map(|(_key, values)| serde_cbor::from_slice::<Vec<T>>(&values).unwrap()),
        )
    }
}

/// Direct singular key-value of T table
///
pub struct SledEventTree<T> {
    tree: sled::Tree,
    marker: PhantomData<T>,
}

impl<T> SledEventTree<T> {
    /// table constructor
    ///
    pub fn new(tree: sled::Tree) -> Self {
        Self {
            tree,
            marker: PhantomData,
        }
    }
}

/// DB "Tables" functionality
///
impl<T> SledEventTree<T>
where
    T: Serialize + DeserializeOwned,
{
    /// get entire Vec<T> in one go
    ///
    pub fn get(&self, id: u64) -> Result<Option<T>, Error> {
        match self.tree.get(key_bytes(id))? {
            Some(value) => Ok(Some(serde_cbor::from_slice(&value)?)),
            None => Ok(None),
        }
    }

    /// check if sprovided `u64` key is present in the db
    ///
    pub fn contains_key(&self, id: u64) -> Result<bool, Error> {
        Ok(self.tree.contains_key(key_bytes(id))?)
    }

    /// check if value `T` is present in the db
    ///
    pub fn contains_value(&self, value: &T) -> bool
    where
        T: PartialEq,
    {
        self.tree
            .iter()
            .flatten()
            .any(|(_, v)| serde_cbor::from_slice::<T>(&v).unwrap().eq(value))
    }

    /// insert `T` with given `key`
    /// Warning! This will rewrite existing value with the same `key`
    ///
    pub fn insert(&self, key: u64, value: &T) -> Result<(), Error> {
        self.tree
            .insert(key_bytes(key), serde_cbor::to_vec(value)?)?;
        Ok(())
    }

    /// iterator over `T` deserialized from the db
    ///
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = T> {
        self.tree
            .iter()
            .flatten()
            .flat_map(|(_, v)| serde_cbor::from_slice(&v))
    }

    /// provides which `u64` key to use to add NEW entry
    ///
    pub fn get_next_key(&self) -> u64 {
        if let Ok(Some((k, _v))) = self.tree.last() {
            u64::from_be_bytes(array_ref!(k, 0, 8).to_owned()) + 1
        } else {
            0
        }
    }

    /// somewhat expensive! gets optional `u64` key for given `&T`
    /// if present in the db
    ///
    pub fn get_key_by_value(&self, value: &T) -> Result<Option<u64>, Error>
    where
        T: Serialize,
    {
        let value = serde_cbor::to_vec(value)?;
        if let Some((key, _)) = self.tree.iter().flatten().find(|(_k, v)| v.eq(&value)) {
            Ok(Some(u64::from_be_bytes(array_ref!(key, 0, 8).to_owned())))
        } else {
            Ok(None)
        }
    }

    /// Combine `get_key_by_value()` and `get_next_key()`
    /// also expensive...
    /// to be used when unsure if identifier is present in the db
    ///
    pub fn designated_key(&self, identifier: &T) -> u64
    where
        T: Serialize,
    {
        if let Ok(Some(key)) = self.get_key_by_value(identifier) {
            key
        } else {
            let key = self.get_next_key();
            self.tree
                .insert(key_bytes(key), serde_cbor::to_vec(identifier).unwrap())
                .unwrap();
            key
        }
    }
}

fn key_bytes(key: u64) -> [u8; 8] {
    key.to_be_bytes()
}
