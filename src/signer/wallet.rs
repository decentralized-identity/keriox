use super::KeyManager;
use crate::{error::Error, keys::PublicKey};
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

impl KeyManager for UnlockedWallet {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        // FIXME: figure out how to fetch signing key with limited trait
        Ok(UnlockedWallet::sign_raw(&self, CURRENT, msg)?)
    }

    // TODO: do we really need this trait not to fail or option out?
    // Now to handle wrong key content we should check for empty vec...
    fn public_key(&self) -> PublicKey {
        match self.get_key(CURRENT) {
            Some(key) => match key.content {
                Content::KeyPair(keys) => PublicKey::new(keys.public_key.public_key),
                Content::Entropy(_) => PublicKey::new(vec![]),
                Content::PublicKey(pk) => PublicKey::new(pk.public_key),
            },
            None => PublicKey::new(vec![]),
        }
    }

    // TODO: do we really need this trait not to fail or option out?
    // Now to handle wrong key content we should check for empty vec...
    fn next_public_key(&self) -> crate::keys::PublicKey {
        match self.get_key(NEXT) {
            Some(key) => match key.content {
                Content::KeyPair(keys) => PublicKey::new(keys.public_key.public_key),
                Content::Entropy(_) => PublicKey::new(vec![]),
                Content::PublicKey(pk) => PublicKey::new(pk.public_key),
            },
            None => PublicKey::new(vec![]),
        }
    }

    fn rotate(&mut self) -> Result<(), Error> {
        if self.next_public_key().key().is_empty() {
            return Err(Error::WalletError(universal_wallet::Error::KeyNotFound));
        }
        if let Some(new_current_set) = self.get_content_by_controller(NEXT) {
            let new_current_content = match new_current_set.clone() {
                Content::KeyPair(kp) => kp.set_controller(vec![CURRENT.into()]),
                _ => return Err(Error::WalletError(universal_wallet::Error::WrongKeyType)),
            };
            // set current to next
            self.set_content(CURRENT, Content::KeyPair(new_current_content));
            // add new next
            let next = KeyPair::random_pair(KeyType::Ed25519VerificationKey2018)?;
            self.set_content(
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
