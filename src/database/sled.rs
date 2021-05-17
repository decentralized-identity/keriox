use std::{
    path::Path,
    marker::PhantomData,
};
use chrono::{DateTime, Local};
use sled::{Db, IVec};
use zerocopy::LayoutVerified;
use serde::{Serialize, de::DeserializeOwned};
use crate::{
    error::Error,
    derivation::attached_signature_code::get_sig_count,
    event::Event,
    prefix::{
        AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix, SelfAddressingPrefix,
        SelfSigningPrefix,
    },
};
use super::EventDatabase;

pub struct SledEventDatabase {
    db: Db,
    // "evts" tree
    events: SledEventTree<Event>,
    // "dtss" tree
    datetime_stamps: SledEventTree<DateTime<Local>>,
    // "sigs" tree
    signatures: SledEventTree<[u8; 64]>, // What's the actual sig size? is it with Derivation
    // "rcts" tree
    receipts_nt: SledEventTree<???>,
    // "ures" tree
    escrowed_receipts_nt: SledEventTree<>,
    // "vrcs" tree
    receipts_t: SledEventTree<>,
    // "vres" tree
    escrowed_receipts_t: SledEventTree<>,
    // "kels" tree
    key_event_logs: SledEventTree<SelfAddressingPrefix>,
    // "pses" tree
    partially_signed_events: SledEventTree<???>,
    // "ooes" tree
    out_of_order_events: SledEventTree<>,
    // "ldes" tree
    likely_duplicious_events: SledEventTree<>,
    // "dels" tree
    diplicitous_events: SledEventTree<>,
}

impl SledEventDatabase {
    pub fn new<'a, P>(path: P) 
        -> Result<Self, Error> 
    where P: Into<&'a Path> {
        Ok(Self {
            db: sled::open(path.into())?,
            ..Self::default()
        })
    }
}

struct SledEventTree<V> {
    tree: sled::Tree,
    marker: PhantomData<V>
}

impl<V> SledEventTree<V> {
    pub fn new(tree: sled::Tree) -> Self {
        Self {
            tree,
            marker: PhantomData,
        }
    }

}

fn key_bytes(key: u64) -> [u8; 8] {
    key.to_be_bytes()
}

impl<V> SledEventTree<V>
where 
    V: Serialize + DeserializeOwned, {

    }

impl EventDatabase for SledEventDatabase {
    type Error = Error;

    fn last_event_at_sn(
        &self,
        pref: &IdentifierPrefix,
        sn: u64) 
            -> Result<Option<Vec<u8>>, Self::Error> {
        // open kels tree
        let kels = self.db.open_tree(b"kels")?;
        // get entry with `sn` key
        match kels.get(key_bytes(sn))? {
            Some(value) => {
                let sap: SelfAddressingPrefix = serde_cbor::from_slice(&value)?;
                let dig_index = format!("{}.{}", pref.to_str(), &sap).as_bytes();
                let events = self.db.open_tree(b"evts")?;
                match events.get(&dig_index)? {
                    Some(event) => Ok(Some(serde_cbor::from_slice(&event)?)),
                    None => Ok(None)
                }
            },
            None => Ok(None)
        }
    }
}