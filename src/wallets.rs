//! bitcoin wallet

use super::*;
use bincode::{deserialize, serialize};
use bitcoincash_addr::*;
// use ed25519_dalek::{Keypair, Signature, Signer, Verifier};
// use untrusted::Input;
// use ring::signature::{Ed25519KeyPair, Signature, KeyPair, UnparsedPublicKey};
use ring::signature::KeyPair;
use ring::signature::{self, Ed25519KeyPair};
// use rand::Rng;
use ring::digest;
use ring::rand;
use ripemd::Ripemd160;
use ripemd::Digest;
use serde::{Deserialize, Serialize};
use sled;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Wallet {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl Wallet {
    /// NewWallet creates and returns a Wallet
    fn new() -> Self {
        // let mut key: [u8; 32] = [0; 32];
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

        let secret_key = pkcs8_bytes.as_ref().to_vec();
        let public_key = key_pair.public_key().as_ref().to_vec();
        Wallet {
            secret_key,
            public_key,
        }
    }

    /// GetAddress returns wallet address
    pub fn get_address(&self) -> String {
        let mut pub_hash: Vec<u8> = self.public_key.clone();
        hash_pub_key(&mut pub_hash);
        let address = Address {
            body: pub_hash,
            scheme: Scheme::Base58,
            hash_type: HashType::Script,
            ..Default::default()
        };
        address.encode().unwrap()
    }
}

/// HashPubKey hashes public key
pub fn hash_pub_key(pubKey: &mut Vec<u8>) {
    let sha256_hash = digest::digest(&digest::SHA256, pubKey);
    *pubKey = sha256_hash.as_ref().to_vec();
    let mut hasher2: Ripemd160 = Ripemd160::new();
    // pubKey.resize(20, 0);
    hasher2.update(&pubKey);
    *pubKey = hasher2.finalize().to_vec();
}

pub struct Wallets {
    wallets: HashMap<String, Wallet>,
}

impl Wallets {
    /// NewWallets creates Wallets and fills it from a file if it exists
    pub fn new() -> Result<Wallets> {
        let mut wlt = Wallets {
            wallets: HashMap::<String, Wallet>::new(),
        };
        let db = sled::open("data/wallets")?;

        for item in db.into_iter() {
            let i = item?;
            let address = String::from_utf8(i.0.to_vec())?;
            let wallet = deserialize(&i.1.to_vec())?;
            wlt.wallets.insert(address, wallet);
        }
        drop(db);
        Ok(wlt)
    }

    /// CreateWallet adds a Wallet to Wallets
    pub fn create_wallet(&mut self) -> String {
        let wallet = Wallet::new();
        let address = wallet.get_address();
        self.wallets.insert(address.clone(), wallet);
        info!("create wallet: {}", address);
        address
    }

    /// GetAddresses returns an array of addresses stored in the wallet file
    pub fn get_all_addresses(&self) -> Vec<String> {
        let mut addresses = Vec::<String>::new();
        for (address, _) in &self.wallets {
            addresses.push(address.clone());
        }
        addresses
    }

    /// GetWallet returns a Wallet by its address
    pub fn get_wallet(&self, address: &str) -> Option<&Wallet> {
        self.wallets.get(address)
    }

    /// SaveToFile saves wallets to a file
    pub fn save_all(&self) -> Result<()> {
        let db = sled::open("data/wallets")?;

        for (address, wallet) in &self.wallets {
            let data = serialize(wallet)?;
            db.insert(address, data)?;
        }

        db.flush()?;
        drop(db);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_create_wallet_and_hash() {
        let w1 = Wallet::new();
        let w2 = Wallet::new();
        assert_ne!(w1, w2);
        assert_ne!(w1.get_address(), w2.get_address());

        let mut p2 = w2.public_key.clone();
        hash_pub_key(&mut p2);
        assert_eq!(p2.len(), 20);
        let pub_key_hash = Address::decode(&w2.get_address()).unwrap().body;
        assert_eq!(pub_key_hash, p2);
    }

    #[test]
    fn test_wallets() {
        let mut ws = Wallets::new().unwrap();
        let wa1 = ws.create_wallet();
        let w1 = ws.get_wallet(&wa1).unwrap().clone();
        ws.save_all().unwrap();

        let ws2 = Wallets::new().unwrap();
        let w2 = ws2.get_wallet(&wa1).unwrap();
        assert_eq!(&w1, w2);
    }

    #[test]
    #[should_panic]
    fn test_wallets_not_exist() {
        let w3 = Wallet::new();
        let ws2 = Wallets::new().unwrap();
        ws2.get_wallet(&w3.get_address()).unwrap();
    }

    #[test]
    fn test_signature() {
        let w = Wallet::new();
        let key_pair = Ed25519KeyPair::from_pkcs8(&w.secret_key).unwrap();
        let sig = key_pair.sign("test".as_bytes());
        // let signature = key_pair.sign("test".as_bytes());
        // assert!(ed25519::verify(
        //     "test".as_bytes(),
        //     &w.public_key,
        //     &signature
        // ));
        let peer_public_key = signature::UnparsedPublicKey::new(&signature::ED25519, &w.public_key);
        assert!(peer_public_key
            .verify("test".as_bytes(), sig.as_ref())
            .is_ok());
    }
}
