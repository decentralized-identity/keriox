mod tables;

use tables::{SledEventTree, SledEventTreeVec};
use std::path::Path;
use crate::{error::Error, event::EventMessage, event_message::{TimestampedEventMessage, signed_event_message::{SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt, TimestampedSignedEventMessage}, KeyEvent}, prefix::IdentifierPrefix};

#[cfg(feature = "query")]
use crate::query::reply::SignedReply;

pub struct SledEventDatabase {
    // "iids" tree
    // this thing is expensive, but everything else is cheeeeeep
    identifiers: SledEventTree<IdentifierPrefix>,
    // "kels" tree
    key_event_logs: SledEventTreeVec<TimestampedSignedEventMessage>,
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

    #[cfg(feature = "query")]
    accepted_rpy: SledEventTreeVec<SignedReply>,

    #[cfg(feature = "query")]
    escrowed_replys: SledEventTreeVec<SignedReply>,
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
            likely_duplicious_events: SledEventTreeVec::new(db.open_tree(b"ldes")?),
            duplicitous_events: SledEventTreeVec::new(db.open_tree(b"dels")?),
            #[cfg(feature = "query")]
            accepted_rpy: SledEventTreeVec::new(db.open_tree(b"knas")?),
            #[cfg(feature = "query")]
            escrowed_replys: SledEventTreeVec::new(db.open_tree(b"knes")?),
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

    pub fn remove_kel_finalized_event(&self, id: &IdentifierPrefix, event: &SignedEventMessage)
        -> Result<(), Error> {
            self.key_event_logs.remove(self.identifiers.designated_key(id), &event.into())
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

    pub fn remove_receipts_nt(&self, id: &IdentifierPrefix)
        -> Result<(), Error> {
            if let Some(receipts) = self.get_receipts_nt(id) {
                for receipt in receipts {
                    self.receipts_nt.remove(self.identifiers.designated_key(id), &receipt)?;
                }
            }
            Ok(())
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

    pub fn remove_escrow_t_receipt(&self, id: &IdentifierPrefix, receipt: &SignedTransferableReceipt)
        -> Result<(), Error> {
            self.escrowed_receipts_t.remove(self.identifiers.designated_key(id), receipt)
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

    pub fn remove_escrow_nt_receipt(&self, id: &IdentifierPrefix, receipt: &SignedNontransferableReceipt)
        -> Result<(), Error> {
            self.escrowed_receipts_nt.remove(self.identifiers.designated_key(id), receipt)
        }

    pub fn add_likely_duplicious_event(&self, event: EventMessage<KeyEvent>, id: &IdentifierPrefix) -> Result<(), Error> {
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

    #[cfg(feature = "query")]
    pub fn update_accepted_reply(
        &self,
        rpy: SignedReply,
        id: &IdentifierPrefix,
    ) -> Result<(), Error> {
        match self
            .accepted_rpy
            .iter_values(self.identifiers.designated_key(id))
        {
            Some(rpys) => {
                let filtered = rpys
                    .filter(|s| s.reply.event.get_route() != rpy.reply.event.get_route())
                    .chain(Some(rpy.clone()).into_iter())
                    .collect();
                self.accepted_rpy
                    .put(self.identifiers.designated_key(id), filtered)
            }
            None => self
                .accepted_rpy
                .push(self.identifiers.designated_key(id), rpy),
        }
    }

    #[cfg(feature = "query")]
    pub fn get_accepted_replys(&self, id: &IdentifierPrefix)
        -> Option<impl DoubleEndedIterator<Item = SignedReply>> {
            self.accepted_rpy.iter_values(self.identifiers.designated_key(id))
        }

    #[cfg(feature = "query")]
    pub fn remove_accepted_reply(&self, id: &IdentifierPrefix, rpy: SignedReply)
        -> Result<(), Error> {
            self.accepted_rpy.remove(self.identifiers.designated_key(id), &rpy)
        }

     #[cfg(feature = "query")]
     pub fn add_escrowed_reply(&self, rpy: SignedReply, id: &IdentifierPrefix)
        -> Result<(), Error> {

            self.escrowed_replys
                .push(self.identifiers.designated_key(id), rpy)
        }

    #[cfg(feature = "query")]
    pub fn get_escrowed_replys(&self, id: &IdentifierPrefix)
        -> Option<impl DoubleEndedIterator<Item = SignedReply>> {
            self.escrowed_replys.iter_values(self.identifiers.designated_key(id))
        }

    #[cfg(feature = "query")]
    pub fn remove_escrowed_reply(&self, id: &IdentifierPrefix, rpy: SignedReply)
        -> Result<(), Error> {
            self.escrowed_replys.remove(self.identifiers.designated_key(id), &rpy)
        }
    
    #[cfg(feature = "query")]
    pub fn get_all_escrowed_replys(&self)
        -> Option<impl DoubleEndedIterator<Item = SignedReply>> {
            self.escrowed_replys.get_all()
        }

}
