use std::marker::PhantomData;
use serde::{Serialize, de::DeserializeOwned};
use arrayref::array_ref;
use crate::{error::Error, prefix::IdentifierPrefix};

pub(crate) struct IdentifierId {
    id: u64,
    prefix: IdentifierPrefix,
}

// Imitates table per key
pub(crate) struct SledEventTreeVec<T> {
    tree: sled::Tree,
    marker: Vec<PhantomData<T>>
}

impl<T> SledEventTreeVec<T> {
    pub fn new(tree: sled::Tree) -> Self {
        Self {
            tree,
            marker: vec!(PhantomData),
        }
    }
}

impl<T> SledEventTreeVec<T>
where
    T: Serialize + DeserializeOwned {
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
            self.tree.insert(key_bytes(key), serde_cbor::to_vec(&value)?)?;
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
                self.put(key, vec!(value))
            }
        }

        /// Appends one `Vec<T>` into DB present one
        /// or `put()`s it if not present as is.
        ///
        pub fn append(&self, key: u64, value: Vec<T>)
            -> Result<(), Error> where T: ToOwned + Clone {
            if let Ok(Some(mut set)) = self.get(key) {
                Ok(set.append(&mut value.to_owned()))
            } else {
                self.put(key, value)
            }
        }
    }

// Direct singular key-value of T
pub(crate) struct SledEventTree<T> {
    tree: sled::Tree,
    marker: PhantomData<T>
}

impl<T> SledEventTree<T> {
    pub fn new(tree: sled::Tree) -> Self {
        Self {
            tree,
            marker: PhantomData,
        }
    }
}

// DB "Tables" functionality
impl<T> SledEventTree<T>
where 
    T: Serialize + DeserializeOwned {
    // we get entire Vec<T> in one go
    pub fn get(&self, id: u64) -> Result<Option<T>, Error> {
        match self.tree.get(key_bytes(id))? {
            Some(value) => Ok(Some(serde_cbor::from_slice(&value)?)),
            None => Ok(None)
        }
    }

    pub fn contains_key(&self, id: u64) -> Result<bool, Error> {
        Ok(self.tree.contains_key(key_bytes(id))?)
    }

    pub fn contains_value(&self, value: &T) -> bool where T: PartialEq {
        self.tree.iter().flatten().find(|(_, v)| serde_cbor::from_slice::<T>(&v).unwrap().eq(value)).is_some()
    }

    pub fn insert(&self, id: u64, value: &T) -> Result<(), Error> {
        self.tree.insert(key_bytes(id), serde_cbor::to_vec(value)?)?;
        Ok(())
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = T> {
        self.tree.iter().flatten().flat_map(|(_, v)| serde_cbor::from_slice(&v))
    }

    pub fn get_next_key(&self) -> u64 {
        if let Ok(Some((k, _v))) = self.tree.last() {
            u64::from_be_bytes(array_ref!(k, 0, 8).to_owned())
        } else { 0 }
    }

    pub fn get_key_by_value(&self, value: &T) 
        -> Result<Option<u64>, Error> 
    where T: PartialEq + Default {
        if let Some((key, _)) = self.tree.iter().flatten()
            .find(|(k, v)| serde_cbor::from_slice::<T>(v).unwrap_or_default().eq(value)) {
                Ok(Some(u64::from_be_bytes(array_ref!(key, 0, 8).to_owned())))
        } else {
            Ok(None)
        }
    }

    pub fn designated_key(&self, identifier: &T)
        -> u64 where T: PartialEq + Default {
        if let Ok(Some(key)) = self.get_key_by_value(identifier) {
            key
        } else {
            self.get_next_key()
        }
    }
}

fn key_bytes(key: u64) -> [u8; 8] {
    key.to_be_bytes()
}
