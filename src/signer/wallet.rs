use super::KeyManager;
use crate::{error::Error, keys::PublicKey};
use std::sync::{Arc, Mutex};
use universal_wallet::{contents::Content, prelude::*};

pub const CURRENT: &str = "current";
const NEXT: &str = "next";
pub const CRYPTO: &str = "crypto";

/// Helper function to populate wallet with properly tagged
/// signing and crypto key pairs
///
pub fn incept_keys(wallet: &mut UnlockedWallet) -> Result<(), Error> {
    let mut current = KeyPair::random_pair(KeyType::Ed25519VerificationKey2018)?;
    current.public_key.controller = vec![CURRENT.into()];
    wallet.set_content(CURRENT, Content::KeyPair(current));
    let mut next = KeyPair::random_pair(KeyType::Ed25519VerificationKey2018)?;
    next.public_key.controller = vec![NEXT.into()];
    wallet.set_content(NEXT, Content::KeyPair(next));
    let mut crypto = KeyPair::random_pair(KeyType::X25519KeyAgreementKey2019)?;
    crypto.public_key.controller = vec![CRYPTO.into()];
    wallet.set_content(CRYPTO, Content::KeyPair(crypto));
    Ok(())
}

/// Returns a public key for a wallet depending on the value of `which`
fn get_public_key(wallet: &UnlockedWallet, which: &str) -> Result<PublicKey, Error> {
    if let Some(key) = wallet.get_key(which) {
        match key.content {
            Content::KeyPair(keys) => {
                let pb_key = keys.public_key.public_key;
                if pb_key.is_empty() {
                    return Err(Error::PublicKeyError("empty public key".into()));
                }
                Ok(PublicKey::new(pb_key))
            }
            Content::Entropy(_) => Err(Error::PublicKeyError("wrong content type".into())),
            Content::PublicKey(pk) => {
                if pk.public_key.is_empty() {
                    return Err(Error::PublicKeyError("empty public key".into()));
                }
                Ok(PublicKey::new(pk.public_key))
            }
        }
    } else {
        Err(Error::PublicKeyError("content not found".into()))
    }
}

impl KeyManager for Arc<Mutex<UnlockedWallet>> {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        // FIXME: figure out how to fetch signing key with limited trait
        Ok(UnlockedWallet::sign_raw(&*self.lock()?, CURRENT, msg)?)
    }

    fn public_key(&self) -> Result<PublicKey, Error> {
        get_public_key(&*self.lock()?, CURRENT)
    }

    fn next_public_key(&self) -> Result<PublicKey, Error> {
        get_public_key(&*self.lock()?, NEXT)
    }

    fn rotate(&mut self) -> Result<(), Error> {
        if self.next_public_key()?.is_empty() {
            return Err(Error::WalletError(universal_wallet::Error::KeyNotFound));
        }
        let mut lock = self.lock()?;
        if let Some(new_current_set) = lock.get_content_by_controller(NEXT) {
            let new_current_content = match new_current_set.clone() {
                Content::KeyPair(kp) => kp.set_controller(vec![CURRENT.into()]),
                _ => return Err(Error::WalletError(universal_wallet::Error::WrongKeyType)),
            };
            // set current to next
            lock
                .set_content(CURRENT, Content::KeyPair(new_current_content));
            // add new next
            let next = KeyPair::random_pair(KeyType::Ed25519VerificationKey2018)?;
            lock.set_content(
                NEXT,
                Content::KeyPair(next.set_controller(vec![NEXT.into()])),
            );
            Ok(())
        } else {
            Err(Error::WalletError(universal_wallet::Error::KeyNotFound))
        }
    }
}

#[test]
fn key_inception_test() {
    let mut wallet = UnlockedWallet::new("test");
    incept_keys(&mut wallet).unwrap();
    // check next
    let next = wallet.get_content_by_controller(NEXT);
    assert!(next.is_some());
    match next.unwrap() {
        Content::KeyPair(_) => (),
        _ => panic!("next is not a KeyPair!"),
    }

    // check current
    let current = wallet.get_content_by_controller(CURRENT);
    assert!(current.is_some());
    match current.unwrap() {
        Content::KeyPair(_) => (),
        _ => panic!("current is not a KeyPair!"),
    }

    // check crypto
    let crypto = wallet.get_content_by_controller(CRYPTO);
    assert!(crypto.is_some());
    match crypto.unwrap() {
        Content::KeyPair(_) => (),
        _ => panic!("crypto is not a KeyPair!"),
    }
}
