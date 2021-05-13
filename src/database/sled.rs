use std::path::Path;
use sled::{Db, IVec, Error};
use zerocopy::LayoutVerified;
use crate::{
    derivation::attached_signature_code::get_sig_count,
    prefix::{
        AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix, SelfAddressingPrefix,
        SelfSigningPrefix,
    },
};
use super::EventDatabase;

pub struct SledEventDatabase {
    db: Db
}

impl SledEventDatabase {
    pub fn new<'a, P>(path: P) 
        -> Result<Self, Error> 
    where P: Into<&'a Path> {
        Ok(Self {
            db: sled::open(path.into())?
        })
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
        // get entry with `sn` key
        if let Ok(last) = kels.get(sn.to_ne_bytes()) {
            match last {
                Some(n) => {
                    let a: Option<(_, LayoutVerified<&[u8], _>)> =
                        LayoutVerified::new_from_prefix(&*n);
                    match b {
                        Some(v) => {},
                        None => {}
                    }
                    Ok(Some(b.bytes().to_vec()))
                },
                None => {}
            }
        }
    }
}