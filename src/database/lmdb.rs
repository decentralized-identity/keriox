use super::EventDatabase;
use crate::{
    error::Error,
    prefix::{
        AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix, SelfAddressingPrefix,
    },
};
use bincode;
use chrono::prelude::*;
use rkv::{
    backend::{
        BackendDatabase, BackendEnvironment, SafeMode, SafeModeDatabase, SafeModeEnvironment,
    },
    value::Type,
    DataError, Manager, MultiStore, Rkv, SingleStore, StoreError, StoreOptions, Value,
};
use serde::Serialize;
use std::path::Path;
use std::sync::{Arc, RwLock};

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

impl LmdbEventDatabase {
    pub fn new<'p, P>(path: P) -> Result<Self, StoreError>
    where
        P: Into<&'p Path>,
    {
        let mut m = Manager::<SafeModeEnvironment>::singleton().write()?;
        let created_arc =
            m.get_or_create_with_capacity(path, 12, Rkv::with_capacity::<SafeMode>)?;
        let env = created_arc.read()?;

        Ok(Self {
            events: env.open_single("evts", StoreOptions::create())?,
            datetime_stamps: env.open_single("dtss", StoreOptions::create())?,
            signatures: env.open_multi("sigs", StoreOptions::create())?,
            receipts_nt: env.open_multi("rcts", StoreOptions::create())?,
            escrowed_receipts_nt: env.open_multi("ures", StoreOptions::create())?,
            receipts_t: env.open_multi("vrcs", StoreOptions::create())?,
            escrowed_receipts_t: env.open_multi("vres", StoreOptions::create())?,
            key_event_logs: env.open_multi("kels", StoreOptions::create())?,
            partially_signed_events: env.open_multi("pses", StoreOptions::create())?,
            out_of_order_events: env.open_multi("ooes", StoreOptions::create())?,
            likely_duplicitous_events: env.open_multi("ldes", StoreOptions::create())?,
            duplicitous_events: env.open_multi("dels", StoreOptions::create())?,
            env: created_arc.clone(),
        })
    }

    fn write_ref_multi<D: Serialize>(
        &self,
        table: &MultiStore<SafeModeDatabase>,
        key: &[u8],
        data: &D,
    ) -> Result<(), StoreError> {
        let lock = self.env.read()?;
        let mut writer = lock.write()?;

        table.put(
            &mut writer,
            &key,
            &Value::Blob(&bincode::serialize(data).unwrap()),
        )?;

        writer.commit()
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

        let dig: SelfAddressingPrefix = match self.key_event_logs.get(&reader, &seq_index)?.last() {
            Some(v) => match v?.1 {
                Value::Blob(b) => {
                    bincode::deserialize(b).map_err(|e| DataError::DecodingError {
                        value_type: Type::Blob,
                        err: e,
                    })?
                }
                _ => {
                    return Err(StoreError::DataError(DataError::UnexpectedType {
                        expected: Type::Blob,
                        actual: Type::from_tag(0u8)?,
                    }))
                }
            },
            None => return Ok(None),
        };

        let dig_index: Vec<u8> = ContentIndex(pref, &dig).into();
        match self.events.get(&reader, &dig_index)? {
            Some(v) => match v {
                Value::Blob(b) => Ok(Some(b.to_vec())),
                _ => Err(StoreError::DataError(DataError::UnexpectedType {
                    expected: Type::Blob,
                    actual: Type::from_tag(0u8)?,
                })),
            },
            None => Ok(None),
        }
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
            self.signatures.put(
                &mut writer,
                &key,
                &Value::Blob(&bincode::serialize(&sig).unwrap()),
            )?;
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
        self.write_ref_multi(
            &self.key_event_logs,
            &Vec::from(SequenceIndex(pref, sn)),
            dig,
        )
    }

    fn escrow_partially_signed_event(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error> {
        self.write_ref_multi(
            &self.partially_signed_events,
            &Vec::from(SequenceIndex(pref, sn)),
            dig,
        )
    }

    fn escrow_out_of_order_event(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error> {
        self.write_ref_multi(
            &self.out_of_order_events,
            &Vec::from(SequenceIndex(pref, sn)),
            dig,
        )
    }

    fn likely_duplicitous_event(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error> {
        self.write_ref_multi(
            &self.likely_duplicitous_events,
            &Vec::from(SequenceIndex(pref, sn)),
            dig,
        )
    }

    fn duplicitous_event(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error> {
        self.write_ref_multi(
            &self.duplicitous_events,
            &Vec::from(SequenceIndex(pref, sn)),
            dig,
        )
    }

    fn add_nt_receipt_for_event(
        &self,
        pref: &IdentifierPrefix,
        dig: &SelfAddressingPrefix,
        signer: &IdentifierPrefix,
        sig: &AttachedSignaturePrefix,
    ) -> Result<(), Self::Error> {
        self.write_ref_multi(
            &self.receipts_nt,
            &Vec::from(ContentIndex(pref, dig)),
            &(signer, sig),
        )
    }

    fn add_t_receipt_for_event(
        &self,
        pref: &IdentifierPrefix,
        dig: &SelfAddressingPrefix,
        signer: &IdentifierPrefix,
        sig: &AttachedSignaturePrefix,
    ) -> Result<(), Self::Error> {
        self.write_ref_multi(
            &self.receipts_t,
            &Vec::from(ContentIndex(pref, dig)),
            &(signer, sig),
        )
    }
}

#[test]
fn basic() -> Result<(), StoreError> {
    use super::test_db;
    use std::fs;
    use tempfile::Builder;

    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();

    let db = LmdbEventDatabase::new(root.path())?;

    test_db(db)
}
