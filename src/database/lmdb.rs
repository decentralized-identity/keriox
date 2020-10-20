use super::EventDatabase;
use crate::prefix::{
    AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix, SelfAddressingPrefix,
};
use chrono::prelude::*;
use rkv::{
    backend::{BackendDatabase, BackendEnvironment, SafeModeDatabase, SafeModeEnvironment},
    value::Type,
    DataError, Manager, MultiStore, Rkv, SingleStore, StoreError, Value,
};
use std::{
    str::FromStr,
    sync::{Arc, RwLock},
};

pub struct LmdbEventDatabase {
    events: SingleStore<SafeModeDatabase>,
    datetime_stamps: SingleStore<SafeModeDatabase>,
    signatures: MultiStore<SafeModeDatabase>,
    receipts_nt: MultiStore<SafeModeDatabase>,
    escrowed_receipts_nt: MultiStore<SafeModeDatabase>,
    receipts_t: MultiStore<SafeModeDatabase>,
    escrowed_receipts_t: MultiStore<SafeModeDatabase>,
    key_event_logs: MultiStore<SafeModeDatabase>,
    partially_signed_events: MultiStore<SafeModeDatabase>,
    out_of_order_events: MultiStore<SafeModeDatabase>,
    likely_duplicitous_events: MultiStore<SafeModeDatabase>,
    duplicitous_events: MultiStore<SafeModeDatabase>,
    env: Arc<RwLock<Rkv<SafeModeEnvironment>>>,
}

pub struct ContentIndex<'a>(&'a IdentifierPrefix, &'a SelfAddressingPrefix);
pub struct SequenceIndex<'a>(&'a IdentifierPrefix, u64);

// useful for using as an index type, but expensive
// TODO: investigate using AsRef<[u8]>
impl From<ContentIndex<'_>> for Vec<u8> {
    fn from(ci: ContentIndex) -> Self {
        [ci.0.to_str(), ".".into(), ci.1.to_str()]
            .concat()
            .into_bytes()
    }
}

impl From<SequenceIndex<'_>> for Vec<u8> {
    fn from(si: SequenceIndex) -> Self {
        format!("{}.{:032}", si.0.to_str(), si.1).into_bytes()
    }
}

impl EventDatabase for LmdbEventDatabase {
    type Error = StoreError;

    fn last_event_at_sn(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        let lock = self.env.read()?;
        let reader = lock.read()?;
        let seq_index: Vec<u8> = SequenceIndex(pref, sn).into();

        let dig = match self.key_event_logs.get(&reader, &seq_index)?.last() {
            Some(v) => match v?.1 {
                Value::Str(s) => SelfAddressingPrefix::from_str(s).map_err(|e| StoreError)?,
                _ => {
                    return Err(StoreError::DataError(DataError::UnexpectedType {
                        expected: Type::Str,
                        actual: Type::from_tag(0u8)?,
                    }))
                }
            },
            None => return Ok(None),
        };

        let dig_index: Vec<u8> = ContentIndex(pref, &dig).into();
        let ret = match self.events.get(&reader, &dig_index)? {
            Some(v) => match v {
                Value::Blob(b) => Ok(Some(b.to_vec())),
                _ => {
                    return Err(StoreError::DataError(DataError::UnexpectedType {
                        expected: Type::Str,
                        actual: Type::from_tag(0u8)?,
                    }))
                }
            },
            None => return Ok(None),
        };

        ret
    }

    fn get_keys_for_prefix(
        &self,
        pref: &IdentifierPrefix,
    ) -> Result<Option<Vec<BasicPrefix>>, Self::Error> {
        let lock = self.env.read()?;
        let reader = lock.read()?;
        let key: Vec<u8> = SequenceIndex(pref, 0).into();

        todo!()
    }

    fn get_children_of_prefix(
        &self,
        pref: &IdentifierPrefix,
    ) -> Result<Option<Vec<IdentifierPrefix>>, Self::Error> {
        todo!()
    }

    fn get_parent_of_prefix(
        &self,
        pref: &IdentifierPrefix,
    ) -> Result<Option<IdentifierPrefix>, Self::Error> {
        todo!()
    }

    fn log_event(
        &self,
        pref: &IdentifierPrefix,
        dig: &SelfAddressingPrefix,
        raw: &[u8],
        sigs: &[AttachedSignaturePrefix],
    ) -> Result<(), Self::Error> {
        let lock = self.env.read()?;
        let mut writer = lock.write()?;
        let key: Vec<u8> = ContentIndex(pref, dig).into();

        // insert timestamp for event
        self.datetime_stamps
            .put(&mut writer, &key, &Value::Str(&Utc::now().to_rfc3339()))?;

        // insert signatures for event
        for sig in sigs.iter() {
            self.signatures
                .put(&mut writer, &key, &Value::Str(&sig.to_str()))?;
        }

        // insert event itself
        self.events.put(&mut writer, &key, &Value::Blob(raw))?;

        writer.commit()
    }

    fn finalise_event(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error> {
        let lock = self.env.read()?;
        let mut writer = lock.write()?;
        let key: Vec<u8> = SequenceIndex(pref, sn).into();

        self.key_event_logs
            .put(&mut writer, &key, &Value::Str(&dig.to_str()))?;

        writer.commit()
    }

    fn escrow_partially_signed_event(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error> {
        let lock = self.env.read()?;
        let mut writer = lock.write()?;
        let key: Vec<u8> = SequenceIndex(pref, sn).into();

        self.partially_signed_events
            .put(&mut writer, &key, &Value::Str(&dig.to_str()))?;

        writer.commit()
    }

    fn escrow_out_of_order_event(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error> {
        let lock = self.env.read()?;
        let mut writer = lock.write()?;
        let key: Vec<u8> = SequenceIndex(pref, sn).into();

        self.partially_signed_events
            .put(&mut writer, &key, &Value::Str(&dig.to_str()))?;

        writer.commit()
    }

    fn likely_duplicitous_event(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error> {
        let lock = self.env.read()?;
        let mut writer = lock.write()?;
        let key: Vec<u8> = SequenceIndex(pref, sn).into();

        self.likely_duplicitous_events
            .put(&mut writer, &key, &Value::Str(&dig.to_str()))?;

        writer.commit()
    }

    fn duplicitous_event(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error> {
        let lock = self.env.read()?;
        let mut writer = lock.write()?;
        let key: Vec<u8> = SequenceIndex(pref, sn).into();

        self.duplicitous_events
            .put(&mut writer, &key, &Value::Str(&dig.to_str()))?;

        writer.commit()
    }

    fn add_nt_receipt_for_event(
        &self,
        pref: &IdentifierPrefix,
        dig: &SelfAddressingPrefix,
        signer: &IdentifierPrefix,
        sig: &AttachedSignaturePrefix,
    ) -> Result<(), Self::Error> {
        let lock = self.env.read()?;
        let mut writer = lock.write()?;
        let key: Vec<u8> = ContentIndex(pref, dig).into();

        self.duplicitous_events.put(
            &mut writer,
            &key,
            &Value::Str(&[signer.to_str(), sig.to_str()].concat()),
        )?;

        writer.commit()
    }

    fn add_t_receipt_for_event(
        &self,
        pref: &IdentifierPrefix,
        dig: &SelfAddressingPrefix,
        signer: &IdentifierPrefix,
        sig: &AttachedSignaturePrefix,
    ) -> Result<(), Self::Error> {
        let lock = self.env.read()?;
        let mut writer = lock.write()?;
        let key: Vec<u8> = ContentIndex(pref, dig).into();

        self.duplicitous_events.put(
            &mut writer,
            &key,
            &Value::Str(&[signer.to_str(), sig.to_str()].concat()),
        )?;

        writer.commit()
    }
}
