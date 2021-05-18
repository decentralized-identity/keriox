mod tables;

use arrayref::array_ref;
use tables::{IdentifierId, SledEventTree, SledEventTreeVec};
use std::path::Path;
use chrono::{DateTime, Local};
use serde::Serialize;
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
    // "iids" tree
    // this thing is expensive, but everything else is cheeeeeep
    identifiers: SledEventTree<IdentifierPrefix>,
    // "evts" tree
    events: SledEventTreeVec<Event>,
    // "dtss" tree
    datetime_stamps: SledEventTreeVec<DateTime<Local>>,
    // "sigs" tree
    signatures: SledEventTreeVec<AttachedSignaturePrefix>,
    // "rcts" tree
    receipts_nt: SledEventTreeVec<???>,
    // "ures" tree
    escrowed_receipts_nt: SledEventTreeVec<>,
    // "vrcs" tree
    receipts_t: SledEventTreeVec<>,
    // "vres" tree
    escrowed_receipts_t: SledEventTreeVec<>,
    // "kels" tree
    key_event_logs: SledEventTreeVec<SelfAddressingPrefix>,
    // "pses" tree
    partially_signed_events: SledEventTreeVec<???>,
    // "ooes" tree
    out_of_order_events: SledEventTreeVec<>,
    // "ldes" tree
    likely_duplicious_events: SledEventTreeVec<>,
    // "dels" tree
    diplicitous_events: SledEventTreeVec<>,
}


impl SledEventDatabase {
    pub fn new<'a, P>(path: P) 
        -> Result<Self, Error> 
    where P: Into<&'a Path> {
        let db = sled::open(path.into())?; 
        Ok(Self {
            identifiers: SledEventTree::new(db.open_tree(b"iids")?),
            events: SledEventTreeVec::new(db.open_tree(b"evts")?),
            datetime_stamps: SledEventTreeVec::new(db.open_tree(b"dtss")?),
            signatures: SledEventTreeVec::new(db.open_tree(b"sigs")?),
            receipts_nt: SledEventTreeVec::new(db.open_tree(b"rcts")?),
            escrowed_receipts_nt: SledEventTreeVec::new(db.open_tree(b"ures")?),
            receipts_t: SledEventTreeVec::new(db.open_tree(b"vrcs")?),
            escrowed_receipts_t: SledEventTreeVec::new(db.open_tree(b"vres")?),
            key_event_logs: SledEventTreeVec::new(db.open_tree(b"kels")?),
            partially_signed_events: SledEventTreeVec::new(db.open_tree(b"pses")?),
            out_of_order_events: SledEventTreeVec::new(db.open_tree(b"ooes")?),
            likely_duplicious_events: SledEventTreeVec::new(db.open_tree(b"ldes")?),
            diplicitous_events: SledEventTreeVec::new(db.open_tree(b"dels")?)
        })
    }

    fn get_identifier_id(&self, prefix: &IdentifierPrefix) -> Result<Option<u64>, Error> {
        self.identifiers.get_key_by_value(prefix)
    }

    fn set_idendifier_id(&self, prefix: &IdentifierPrefix) -> Result<(), Error> {
        let value = prefix.to_str().as_bytes();
        if self.identifiers.contains_value(prefix) {
            Ok(())
        } else {
            let key = self.identifiers.get_next_key();
            self.identifiers.insert(key, prefix)
        }
    }
}



impl EventDatabase for SledEventDatabase {
    type Error = Error;

    fn last_event_at_sn(
        &self,
        pref: &IdentifierPrefix,
        sn: u64) 
            -> Result<Option<Vec<u8>>, Self::Error> {
        if let Some(key) = self.identifiers.get_key_by_value(pref)? {
            if let Some(events) = self.events.get(key)? {
                if let Some(event) = events.iter().find(|e| e.sn.eq(&sn)) {
                    // FIXME 1: this again serializes into json - opposite to `log_event()`
                    // FIXME 2: will this be last event?
                    Ok(Some(serde_json::to_string(&event)?.as_bytes().to_vec()))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
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
        let key = self.identifiers.designated_key(prefix);
        self.signatures.append(key, sigs.to_vec())?;
        // FIXME: this will work only in case `raw` is json serialized
        self.events.push(key, serde_json::from_slice(raw)?)
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