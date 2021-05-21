mod tables;

use tables::{SledEventTree, SledEventTreeVec};
use std::path::Path;
use crate::{
    error::Error,
    event::{
        Event,
        TimestampedEvent,
        TimestampedSignedEventMessage,
        event_data::{
            ReceiptNonTransferable,
            ReceiptTransferable
        },
    }, prefix::{
        IdentifierPrefix,
        SelfAddressingPrefix,
    },
    event_message::SignedEventMessage,
};

pub struct SledEventDatabase {
    // "iids" tree
    // this thing is expensive, but everything else is cheeeeeep
    identifiers: SledEventTree<IdentifierPrefix>,
    // "evts" tree
    events: SledEventTreeVec<TimestampedEvent>,
    // "sevts" tree
    signed_events: SledEventTreeVec<TimestampedSignedEventMessage>,
    // "rcts" tree
    receipts_nt: SledEventTreeVec<ReceiptNonTransferable>,
    // "ures" tree
    escrowed_receipts_nt: SledEventTreeVec<ReceiptNonTransferable>,
    // "vrcs" tree
    receipts_t: SledEventTreeVec<ReceiptTransferable>,
    // "vres" tree
    escrowed_receipts_t: SledEventTreeVec<ReceiptTransferable>,
    // "kels" tree
    key_event_logs: SledEventTreeVec<SelfAddressingPrefix>,
    // "pses" tree
    partially_signed_events: SledEventTreeVec<TimestampedEvent>,
    // "ooes" tree
    out_of_order_events: SledEventTreeVec<TimestampedEvent>,
    // "ldes" tree
    likely_duplicious_events: SledEventTreeVec<TimestampedEvent>,
    // "dels" tree
    duplicitous_events: SledEventTreeVec<TimestampedEvent>,
}


impl SledEventDatabase {
    pub fn new<'a, P>(path: P) 
        -> Result<Self, Error> 
    where P: Into<&'a Path> {
        let db = sled::open(path.into())?; 
        Ok(Self {
            identifiers: SledEventTree::new(db.open_tree(b"iids")?),
            events: SledEventTreeVec::new(db.open_tree(b"evts")?),
            signed_events: SledEventTreeVec::new(db.open_tree(b"sevets")?),
            receipts_nt: SledEventTreeVec::new(db.open_tree(b"rcts")?),
            escrowed_receipts_nt: SledEventTreeVec::new(db.open_tree(b"ures")?),
            receipts_t: SledEventTreeVec::new(db.open_tree(b"vrcs")?),
            escrowed_receipts_t: SledEventTreeVec::new(db.open_tree(b"vres")?),
            key_event_logs: SledEventTreeVec::new(db.open_tree(b"kels")?),
            partially_signed_events: SledEventTreeVec::new(db.open_tree(b"pses")?),
            out_of_order_events: SledEventTreeVec::new(db.open_tree(b"ooes")?),
            likely_duplicious_events: SledEventTreeVec::new(db.open_tree(b"ldes")?),
            duplicitous_events: SledEventTreeVec::new(db.open_tree(b"dels")?)
        })
    }

    pub fn add_new_event(&self, event: Event, id: &IdentifierPrefix) -> Result<(), Error> {
        self.events.push(self.identifiers.designated_key(id), event.into())
    }

    pub fn get_events(&self, id: &IdentifierPrefix) -> Option<impl DoubleEndedIterator<Item = TimestampedEvent>> {
        self.events.iter_values(self.identifiers.designated_key(id))
    }

    pub fn add_new_signed_event_message(&self, event: SignedEventMessage, id: &IdentifierPrefix)
        -> Result<(), Error> {
            self.signed_events.push(self.identifiers.designated_key(id), event.into())
        }

    pub fn get_signed_event_messages(&self, id: &IdentifierPrefix)
        -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
            self.signed_events.iter_values(self.identifiers.designated_key(id))
        }

    pub fn add_escrow_t_receipt(&self, receipt: ReceiptTransferable, id: &IdentifierPrefix)
        -> Result<(), Error> {
            self.escrowed_receipts_t
                .push(self.identifiers.designated_key(id), receipt)
        }

    pub fn get_escrow_t_receipts(&self, id: &IdentifierPrefix)
        -> Option<impl DoubleEndedIterator<Item = ReceiptTransferable>> {
            self.escrowed_receipts_t.iter_values(self.identifiers.designated_key(id))
        }

    pub fn add_escrow_nt_receipt(&self, receipt: ReceiptNonTransferable, id: &IdentifierPrefix)
        -> Result<(), Error> {
            self.escrowed_receipts_nt
                .push(self.identifiers.designated_key(id), receipt)
        }

    pub fn get_escrow_nt_receipts(&self, id: &IdentifierPrefix)
        -> Option<impl DoubleEndedIterator<Item = ReceiptNonTransferable>> {
            self.escrowed_receipts_nt.iter_values(self.identifiers.designated_key(id))
        }

    pub fn add_outoforder_event(&self, event: Event, id: &IdentifierPrefix) -> Result<(), Error> {
        self.out_of_order_events.push(self.identifiers.designated_key(id), event.into())
    }

    pub fn get_outoforder_events(&self, id: &IdentifierPrefix)
        -> Option<impl DoubleEndedIterator<Item = TimestampedEvent>> {
            self.out_of_order_events.iter_values(self.identifiers.designated_key(id))
        }

    pub fn add_partially_signed_event(&self, event: Event, id: &IdentifierPrefix) -> Result<(), Error> {
        self.partially_signed_events.push(self.identifiers.designated_key(id), event.into())
    }

    pub fn get_partially_signed_events(&self, id: &IdentifierPrefix)
        -> Option<impl DoubleEndedIterator<Item = TimestampedEvent>> {
            self.partially_signed_events.iter_values(self.identifiers.designated_key(id))
        }

    pub fn add_likely_duplicious_event(&self, event: Event, id: &IdentifierPrefix) -> Result<(), Error> {
        self.likely_duplicious_events.push(self.identifiers.designated_key(id), event.into())
    }

    pub fn get_likely_duplicitous_events(&self, id: &IdentifierPrefix)
        -> Option<impl DoubleEndedIterator<Item = TimestampedEvent>> {
            self.likely_duplicious_events.iter_values(self.identifiers.designated_key(id))
        }

    pub fn add_duplicious_event(&self, event: Event, id: &IdentifierPrefix) -> Result<(), Error> {
        self.duplicitous_events.push(self.identifiers.designated_key(id), event.into())
    }

    pub fn get_duplicious_events(&self, id: &IdentifierPrefix)
        -> Option<impl DoubleEndedIterator<Item = TimestampedEvent>> {
            self.duplicitous_events.iter_values(self.identifiers.designated_key(id))
        }
}

/*  DEPRECATED: since 0.7
impl EventDatabase for SledEventDatabase {
    type Error = Error;

    fn last_event_at_sn(
        &self,
        pref: &IdentifierPrefix,
        sn: u64) 
            -> Result<Option<Vec<u8>>, Self::Error> {
        if let Some(key) = self.identifiers.get_key_by_value(pref)? {
            if let Some(events) = self.events.get(key)? {
                if let Some(event) = events.iter().find(|e| e.event.sn.eq(&sn)) {
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
        if let Some(key) = self.identifiers.get_key_by_value(id)? {
            // FIXME 1: everything is again json -> bytes serialized
            if let Some(kels) = self.key_event_logs.get(key)? {
                let mut accum: Vec<u8> = Vec::new();
                kels.iter()
                    .map(|k| accum.extend(serde_json::to_string(k)
                    .unwrap_or_default().as_bytes())).for_each(drop);
                if let Some(events) = self.events.get(key)? {
                    events.iter()
                        .map(|e| accum.extend(serde_json::to_string(e)
                        .unwrap_or_default().as_bytes())).for_each(drop);
                    if let Some(signatures) = self.signatures.get(key)? {
                        signatures.iter()
                            .map(|s| accum.extend(serde_json::to_string(s)
                            .unwrap_or_default().as_bytes())).for_each(drop);
                    }
                    // FIXME 2: add seals too
                }
                Ok(Some(accum))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    fn log_event(
        &self,
        prefix: &IdentifierPrefix,
        _dig: &SelfAddressingPrefix,
        raw: &[u8],
        sigs: &[AttachedSignaturePrefix],
    ) -> Result<(), Self::Error> {
        let key = self.identifiers.designated_key(prefix);
        self.signatures.append(key, sigs.to_vec())?;
        // FIXME 1: this will work only in case `raw` is json serialized
        self.events.push(key, serde_json::from_slice(raw)?)
        // FIXME 2: does timestamps included into sigs/event
        //      or need to be pushed seperately + linked?
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
        // FIXME: whe sn is here?
        sn: u64,
        validator: &IdentifierPrefix,
    ) -> Result<bool, Self::Error> {
        if let Some(validator_key) = self.identifiers.get_key_by_value(validator)? {
            if let Some(receipts) = self.receipts_t.get(validator_key)? {
                // logic for receipt -> pref validation
                match pref {
                    IdentifierPrefix::SelfAddressing(p) =>
                        Ok(receipts.iter()
                        .find(|v| 
                            v.receipted_event_digest.eq(p))
                            .is_some()),
                    _ => Ok(false)
                }
            } else { Ok(false) }
        } else { Ok(false) }
    }
}
*/