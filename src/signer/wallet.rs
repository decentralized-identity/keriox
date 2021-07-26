use universal_wallet::{
    prelude::*,
    contents::Content,
};
use super::KeyManager;
use crate::{
    keys::Key,
    error::Error,
};

pub const CURRENT: &str = "current";
const NEXT: &str = "next";
pub const CRYPTO: &str = "crypto";

/// Helper function to populate wallet with properly tagged
/// signing and crypto key pairs
///
pub fn incept_keys(wallet: &mut UnlockedWallet) -> Result<(), Error> {
    wallet.set_content(CURRENT, Content::KeyPair(KeyPair::random_pair(KeyType::Ed25519VerificationKey2018)?));
    wallet.set_content(NEXT, Content::KeyPair(KeyPair::random_pair(KeyType::Ed25519VerificationKey2018)?));
    wallet.set_content(CRYPTO, Content::KeyPair(KeyPair::random_pair(KeyType::X25519KeyAgreementKey2019)?));
    Ok(())
}

impl KeyManager for UnlockedWallet {
    fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, Error> {
        // FIXME: figure out how to fetch signing key with limited trait
        Ok(UnlockedWallet::sign_raw(&self, CURRENT, msg)?)
    }

    // TODO: do we really need this trait not to fail or option out?
    // Now to handle wrong key content we should check for empty vec...
    fn public_key(&self) -> Key {
        match self.get_key(CURRENT) {
            Some(key) => match key.content {
                Content::KeyPair(keys) =>
                    Key::new(keys.public_key.public_key),
                Content::Entropy(_) =>
                    Key::new(vec!()),
                Content::PublicKey(pk) =>
                    Key::new(pk.public_key)
            },
            None => Key::new(vec!())
        }
    }

    // TODO: do we really need this trait not to fail or option out?
    // Now to handle wrong key content we should check for empty vec...
    fn next_public_key(&self) -> crate::keys::Key {
        match self.get_key(NEXT) {
            Some(key) => match key.content {
                Content::KeyPair(keys) =>
                    Key::new(keys.public_key.public_key),
                Content::Entropy(_) =>
                    Key::new(vec!()),
                Content::PublicKey(pk) =>
                    Key::new(pk.public_key)
            },
            None => Key::new(vec!())
        }
    }

    fn rotate(&mut self) -> Result<(), Error> {
        if self.next_public_key().key().is_empty() {
            return Err(Error::WalletError(universal_wallet::Error::KeyNotFound));
        }
        if let Some(new_current_set) = self.get_key_by_controller(&NEXT) {
            let new_current_content = match new_current_set.content {
                Content::KeyPair(kp) => kp.set_controller(vec!(CURRENT.into())),
                _ => return Err(Error::WalletError(universal_wallet::Error::WrongKeyType))
            };
            // set current to next
            self.set_content(&CURRENT, Content::KeyPair(new_current_content));
            // add new next
            let next = KeyPair::random_pair(KeyType::Ed25519VerificationKey2018)?;
            self.set_content(&NEXT, Content::KeyPair(next.set_controller(vec!(NEXT.into()))));
        Ok(())
        } else {
            Err(Error::WalletError(universal_wallet::Error::KeyNotFound))
        }
    }
}
