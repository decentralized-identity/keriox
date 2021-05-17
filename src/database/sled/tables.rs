use std::marker::PhantomData;

use serde::{Serialize, de::DeserializeOwned};

use crate::{error::Error, prefix::IdentifierPrefix};

pub(crate) struct IdentifierId {
    prefix: IdentifierPrefix,
    id: u64,
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

    pub fn get_other_than_u64(&self, key: impl AsRef<[u8]>) -> Result<Option<T>, Error> {
        match self.tree.get(key)? {
            Some(v) => Ok(Some(serde_cbor::from_slice(&v)?)),
            None => Ok(None)
        }
    }

    pub fn contains_key(&self, id: u64) -> Result<bool, Error> {
        Ok(self.tree.contains_key(key_bytes(id))?)
    }

    pub fn insert(&self, id: u64, value: T) -> Result<(), Error> {
        self.tree.insert(key_bytes(id), serde_cbor::to_vec(&value)?)?;
        Ok(())
    }

    pub fn insert_other_than_u64(&self, key: impl AsRef<[u8]>, value: T) -> Result<(), Error> {
        self.tree.insert(key, serde_cbor::to_vec(&value)?)?;
        Ok(())
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = T> {
        self.tree.iter().flatten().flat_map(|(_, v)| serde_cbor::from_slice(&v))
    }

}

fn key_bytes(key: u64) -> [u8; 8] {
    key.to_be_bytes()
}
