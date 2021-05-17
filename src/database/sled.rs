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

struct IdentifierId {
    prefix: IdentifierPrefix,
    id: u64,
}

pub struct SledEventDatabase {
    db: Db,
    // "iids" tree
    identifiers: SledEventTree<IdentifierId>,
    // "evts" tree
    events: SledEventTree<Event>,
    // "dtss" tree
    datetime_stamps: SledEventTree<DateTime<Local>>,
    // "sigs" tree
    signatures: SledEventTree<AttachedSignaturePrefix>,
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

fn key_bytes(key: u64) -> [u8; 8] {
    key.to_be_bytes()
}

impl SledEventDatabase {
    pub fn new<'a, P>(path: P) 
        -> Result<Self, Error> 
    where P: Into<&'a Path> {
        let db = sled::open(path.into())?; 
        Ok(Self {
            db,
            identifiers: SledEventTree::new(db.open_tree(b"iids")?),
            events: SledEventTree::new(db.open_tree(b"evts")?),
            datetime_stamps: SledEventTree::new(db.open_tree(b"dtss")?),
            signatures: SledEventTree::new(db.open_tree(b"sigs")?),
            receipts_nt: SledEventTree::new(db.open_tree(b"rcts")?),
            escrowed_receipts_nt: SledEventTree::new(db.open_tree(b"ures")?),
            receipts_t: SledEventTree::new(db.open_tree(b"vrcs")?),
            escrowed_receipts_t: SledEventTree::new(db.open_tree(b"vres")?),
            key_event_logs: SledEventTree::new(db.open_tree(b"kels")?),
            partially_signed_events: SledEventTree::new(db.open_tree(b"pses")?),
            out_of_order_events: SledEventTree::new(db.open_tree(b"ooes")?),
            likely_duplicious_events: SledEventTree::new(db.open_tree(b"ldes")?),
            diplicitous_events: SledEventTree::new(db.open_tree(b"dels")?)
        })
    }

    fn get_identifier_id(&self, prefix: &IdentifierPrefix) -> Result<u64, Error> {
        match self.db.open_tree(b"iids")?.get(prefix.to_str().as_bytes())? {
            Some(id) => Ok(serde_cbor::from_slice(&id)?),
            None => Err(Error::NotIndexedError)
        }
    }

    fn set_idendifier_id(&self, prefix: &IdentifierPrefix) -> Result<(), Error> {
        let key = prefix.to_str().as_bytes();
        let tree = self.db.open_tree(b"iids")?;
        if tree.contains_key(key)? { return Err(Error::IdentifierPresentError); }

        let next_id = match tree.last()? {
            Some((max, _)) => {
                let c_max: u64 = serde_cbor::from_slice(&max)?;
                c_max + 1u64
            },
            None => 0u64
        };

        match tree.insert(key, serde_cbor::to_vec(&next_id)?)? {
            Some(_) => Ok(()),
            None => Err(Error::IdentifierPresentError)
        }
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

impl<V> SledEventTree<V>
where 
    V: Serialize + DeserializeOwned, {
    pub fn get(&self, id: u64) -> Result<Option<V>, Error> {
        match self.tree.get(key_bytes(id))? {
            Some(value) => Ok(Some(serde_cbor::from_slice(&value)?)),
            None => Ok(None)
        }
    }

    pub fn contains_key(&self, id: u64) -> Result<bool, Error> {
        Ok(self.tree.contains_key(key_bytes(id))?)
    }

    pub fn insert(&self, id: u64, value: V) -> Result<(), Error> {
        self.tree.insert(key_bytes(id), serde_cbor::to_vec(&value)?)?;
        Ok(())
    }

    pub fn insert_other_than_u64(&self, key: impl AsRef<[u8]>, value: V) -> Result<(), Error> {
        self.tree.insert(key, serde_cbor::to_vec(&value)?)?;
        Ok(())
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = V> {
        self.tree.iter().flatten().flat_map(|(_, v)| serde_cbor::from_slice(&v))
    }

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
        let id = self.get_identifier_id(pref)?;
        // get entry with `sn` key
        match kels.get(key_bytes(id))? { todo!();
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

    fn get_kerl(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Self::Error> {
        todo!()
    }

    fn log_event(
        &self,
        prefix: &IdentifierPrefix,
        dig: &SelfAddressingPrefix,
        raw: &[u8],
        sigs: &[AttachedSignaturePrefix],
    ) -> Result<(), Self::Error> {
        let key = key_bytes(self.get_identifier_id(prefix)?);
        let dts = self.db.open_tree(b"dtss")?;
        dts.insert(key, Local::now().to_rfc3339().as_bytes())?;
        let sdb = self.db.open_tree(b"sigs")?;
        sigs.iter().map(|sig| sdb.insert(key, sig))
    }

    fn finalise_event(
        &self,
        prefix: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn escrow_partially_signed_event(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn escrow_out_of_order_event(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn likely_duplicitous_event(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn duplicitous_event(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn add_nt_receipt_for_event(
        &self,
        pref: &IdentifierPrefix,
        dig: &SelfAddressingPrefix,
        signer: &BasicPrefix,
        sig: &SelfSigningPrefix,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn add_t_receipt_for_event(
        &self,
        pref: &IdentifierPrefix,
        dig: &SelfAddressingPrefix,
        signer: &IdentifierPrefix,
        sig: &AttachedSignaturePrefix,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn escrow_nt_receipt(
        &self,
        pref: &IdentifierPrefix,
        dig: &SelfAddressingPrefix,
        signer: &BasicPrefix,
        sig: &SelfSigningPrefix,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn escrow_t_receipt(
        &self,
        pref: &IdentifierPrefix,
        dig: &SelfAddressingPrefix,
        signer: &IdentifierPrefix,
        sig: &AttachedSignaturePrefix,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn has_receipt(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        validator: &IdentifierPrefix,
    ) -> Result<bool, Self::Error> {
        todo!()
    }
}