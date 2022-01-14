use std::path::Path;
use std::sync::Arc;

use crate::query::reply::{ReplyEvent, SignedReply};
use crate::query::{
    key_state_notice::KeyStateNotice,
    query::{QueryData, SignedQuery},
    ReplyType, Route,
};

use crate::{
    database::sled::SledEventDatabase,
    derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    event::SerializationFormats,
    prefix::{BasicPrefix, IdentifierPrefix},
    processor::EventProcessor,
    signer::{CryptoBox, KeyManager},
};

pub struct Witness {
    pub prefix: BasicPrefix,
    signer: CryptoBox,
    pub processor: EventProcessor,
}

impl Witness {
    pub fn new(path: &Path) -> Result<Self, Error> {
        let signer = CryptoBox::new()?;
        let processor = {
            let witness_db = Arc::new(SledEventDatabase::new(path).unwrap());
            EventProcessor::new(witness_db.clone())
        };
        let prefix = Basic::Ed25519.derive(signer.public_key());
        Ok(Self {
            prefix,
            signer,
            processor,
        })
    }

    pub fn get_ksn_for_prefix(&self, prefix: &IdentifierPrefix) -> Result<SignedReply, Error> {
        let state = self.processor.compute_state(prefix).unwrap().unwrap();
        let ksn = KeyStateNotice::new_ksn(state, SerializationFormats::JSON);
        let rpy = ReplyEvent::new_reply(
            ksn,
            Route::ReplyKsn(IdentifierPrefix::Basic(self.prefix.clone())),
            SelfAddressing::Blake3_256,
            SerializationFormats::JSON,
        )?;

        let signature =
            SelfSigning::Ed25519Sha512.derive(self.signer.sign(&rpy.serialize()?).unwrap());
        Ok(SignedReply::new_nontrans(
            rpy,
            self.prefix.clone(),
            signature,
        ))
    }

    pub fn process_signed_query(&self, qr: SignedQuery) -> Result<ReplyType, Error> {
        let signatures = qr.signatures;
        // check signatures
        let kc = self
            .processor
            .compute_state(&qr.signer)?
            .ok_or(Error::SemanticError("No identifier in db".into()))?
            .current;

        if kc.verify(&qr.envelope.serialize().unwrap(), &signatures)? {
            // TODO check timestamps
            // unpack and check what's inside
            let route = qr.envelope.event.get_route();
            self.process_query(route, qr.envelope.event.get_query_data())
        } else {
            Err(Error::SignatureVerificationError)
        }
    }

    #[cfg(feature = "query")]
    fn process_query(&self, route: Route, qr: QueryData) -> Result<ReplyType, Error> {
        match route {
            Route::Log => {
                Ok(ReplyType::Kel(self.processor.get_kerl(&qr.data.i)?.ok_or(
                    Error::SemanticError("No identifier in db".into()),
                )?))
            }
            Route::Ksn => {
                let i = qr.data.i;
                // return reply message with ksn inside
                let state = self
                    .processor
                    .compute_state(&i)
                    .unwrap()
                    .ok_or(Error::SemanticError("No id in database".into()))?;
                let ksn = KeyStateNotice::new_ksn(state, SerializationFormats::JSON);
                let rpy = ReplyEvent::new_reply(
                    ksn,
                    Route::ReplyKsn(IdentifierPrefix::Basic(self.prefix.clone())),
                    SelfAddressing::Blake3_256,
                    SerializationFormats::JSON,
                )?;
                let signature = self.signer.sign(&rpy.serialize()?)?;
                let rpy = SignedReply::new_nontrans(
                    rpy,
                    self.prefix.clone(),
                    SelfSigning::Ed25519Sha512.derive(signature),
                );
                Ok(ReplyType::Rep(rpy))
            }
            _ => todo!(),
        }
    }
}
