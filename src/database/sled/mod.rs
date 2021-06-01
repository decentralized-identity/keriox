mod tables;

use tables::{SledEventTree, SledEventTreeVec};
use std::path::Path;
use crate::{error::Error, event::EventMessage, event_message::{SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt, TimestampedEventMessage, TimestampedSignedEventMessage}, prefix::IdentifierPrefix};

pub struct SledEventDatabase {
    // "iids" tree
    // this thing is expensive, but everything else is cheeeeeep
    identifiers: SledEventTree<IdentifierPrefix>,
    // "kels" tree
    key_event_logs: SledEventTreeVec<TimestampedSignedEventMessage>,
    // "pses" tree
    partially_signed_events: SledEventTreeVec<TimestampedSignedEventMessage>,
    // "ooes" tree
    out_of_order_events: SledEventTreeVec<TimestampedSignedEventMessage>,
    // "ldes" tree
    likely_duplicious_events: SledEventTreeVec<TimestampedEventMessage>,
    // "dels" tree
    duplicitous_events: SledEventTreeVec<TimestampedSignedEventMessage>,
    // "rcts" tree
    receipts_nt: SledEventTreeVec<SignedNontransferableReceipt>,
    // "ures" tree
    escrowed_receipts_nt: SledEventTreeVec<SignedNontransferableReceipt>,
    // "vrcs" tree
    receipts_t: SledEventTreeVec<SignedTransferableReceipt>,
    // "vres" tree
    escrowed_receipts_t: SledEventTreeVec<SignedTransferableReceipt>,
}


impl SledEventDatabase {
    pub fn new<'a, P>(path: P) 
        -> Result<Self, Error> 
    where P: Into<&'a Path> {
        let db = sled::open(path.into())?; 
        Ok(Self {
            identifiers: SledEventTree::new(db.open_tree(b"iids")?),
            escrowed_receipts_nt: SledEventTreeVec::new(db.open_tree(b"ures")?),
            receipts_t: SledEventTreeVec::new(db.open_tree(b"vrcs")?),
            escrowed_receipts_t: SledEventTreeVec::new(db.open_tree(b"vres")?),
            receipts_nt: SledEventTreeVec::new(db.open_tree(b"rcts")?),
            key_event_logs: SledEventTreeVec::new(db.open_tree(b"kels")?),
            partially_signed_events: SledEventTreeVec::new(db.open_tree(b"pses")?),
            out_of_order_events: SledEventTreeVec::new(db.open_tree(b"ooes")?),
            likely_duplicious_events: SledEventTreeVec::new(db.open_tree(b"ldes")?),
            duplicitous_events: SledEventTreeVec::new(db.open_tree(b"dels")?)
        })
    }

    pub fn add_kel_finalized_event(&self, event: SignedEventMessage, id: &IdentifierPrefix)
        -> Result<(), Error> {
            self.key_event_logs.push(self.identifiers.designated_key(id), event.into())
        }
    
    pub fn get_kel_finalized_events(&self, id: &IdentifierPrefix)
        -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
            self.key_event_logs.iter_values(self.identifiers.designated_key(id))
        }

    pub fn add_receipt_t(&self, receipt: SignedTransferableReceipt, id: &IdentifierPrefix)
        -> Result<(), Error> {
            self.receipts_t
                .push(self.identifiers.designated_key(id), receipt)
        }

    pub fn get_receipts_t(&self, id: &IdentifierPrefix)
        -> Option<impl DoubleEndedIterator<Item = SignedTransferableReceipt>> {
            self.receipts_t.iter_values(self.identifiers.designated_key(id))
        }

    pub fn add_receipt_nt(&self, receipt: SignedNontransferableReceipt, id: &IdentifierPrefix)
        -> Result<(), Error> {
            self.receipts_nt
                .push(self.identifiers.designated_key(id), receipt)
        }

    pub fn get_receipts_nt(&self, id: &IdentifierPrefix)
        -> Option<impl DoubleEndedIterator<Item = SignedNontransferableReceipt>> {
            self.receipts_nt.iter_values(self.identifiers.designated_key(id))
        }

    pub fn add_escrow_t_receipt(&self, receipt: SignedTransferableReceipt, id: &IdentifierPrefix)
        -> Result<(), Error> {
            self.escrowed_receipts_t
                .push(self.identifiers.designated_key(id), receipt)
        }

    pub fn get_escrow_t_receipts(&self, id: &IdentifierPrefix)
        -> Option<impl DoubleEndedIterator<Item = SignedTransferableReceipt>> {
            self.escrowed_receipts_t.iter_values(self.identifiers.designated_key(id))
        }

    pub fn add_escrow_nt_receipt(&self, receipt: SignedNontransferableReceipt, id: &IdentifierPrefix)
        -> Result<(), Error> {
            self.escrowed_receipts_nt
                .push(self.identifiers.designated_key(id), receipt)
        }

    pub fn get_escrow_nt_receipts(&self, id: &IdentifierPrefix)
        -> Option<impl DoubleEndedIterator<Item = SignedNontransferableReceipt>> {
            self.escrowed_receipts_nt.iter_values(self.identifiers.designated_key(id))
        }

    pub fn add_outoforder_event(&self, event: SignedEventMessage, id: &IdentifierPrefix) -> Result<(), Error> {
        self.out_of_order_events.push(self.identifiers.designated_key(id), event.into())
    }

    pub fn get_outoforder_events(&self, id: &IdentifierPrefix)
        -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
            self.out_of_order_events.iter_values(self.identifiers.designated_key(id))
        }

    pub fn add_partially_signed_event(&self, event: SignedEventMessage, id: &IdentifierPrefix) -> Result<(), Error> {
        self.partially_signed_events.push(self.identifiers.designated_key(id), event.into())
    }

    pub fn get_partially_signed_events(&self, id: &IdentifierPrefix)
        -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
            self.partially_signed_events.iter_values(self.identifiers.designated_key(id))
        }

    pub fn add_likely_duplicious_event(&self, event: EventMessage, id: &IdentifierPrefix) -> Result<(), Error> {
        self.likely_duplicious_events.push(self.identifiers.designated_key(id), event.into())
    }

    pub fn get_likely_duplicitous_events(&self, id: &IdentifierPrefix)
        -> Option<impl DoubleEndedIterator<Item = TimestampedEventMessage>> {
            self.likely_duplicious_events.iter_values(self.identifiers.designated_key(id))
        }

    pub fn add_duplicious_event(&self, event: SignedEventMessage, id: &IdentifierPrefix) -> Result<(), Error> {
        self.duplicitous_events.push(self.identifiers.designated_key(id), event.into())
    }

    pub fn get_duplicious_events(&self, id: &IdentifierPrefix)
        -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
            self.duplicitous_events.iter_values(self.identifiers.designated_key(id))
        }

    pub fn remove_rct(&self, id: &IdentifierPrefix, sn: u64) -> Result<(), Error> {
        let current: Vec<SignedTransferableReceipt> = self.get_escrow_t_receipts(id).unwrap().filter(|ev| ev.body.event.sn != sn).collect();
        self.escrowed_receipts_t.put(self.identifiers.designated_key(id), current)?;
        
        Ok(())
    }
}
