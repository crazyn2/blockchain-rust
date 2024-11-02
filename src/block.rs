//! Block implement of blockchain

use super::*;
use crate::transaction::Transaction;
use bincode::serialize;
use merkle_cbt::merkle_tree::Merge;
use merkle_cbt::merkle_tree::CBMT;
use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

const TARGET_HEXS: usize = 4;

/// Block keeps block headers
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    timestamp: u128,
    transactions: Vec<Transaction>,
    prev_block_hash: String,
    hash: String,
    nonce: i32,
    height: i32,
}

impl Block {
    pub fn get_hash(&self) -> String {
        self.hash.clone()
    }

    pub fn get_prev_hash(&self) -> String {
        self.prev_block_hash.clone()
    }

    pub fn get_transaction(&self) -> &Vec<Transaction> {
        &self.transactions
    }

    pub fn get_height(&self) -> i32 {
        self.height
    }

    /// NewBlock creates and returns Block
    pub fn new_block(
        transactions: Vec<Transaction>,
        prev_block_hash: String,
        height: i32,
    ) -> Result<Block> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_millis();
        let mut block = Block {
            timestamp,
            transactions,
            prev_block_hash,
            hash: String::new(),
            nonce: 0,
            height,
        };
        block.run_proof_of_work()?;
        Ok(block)
    }

    /// NewGenesisBlock creates and returns genesis Block
    pub fn new_genesis_block(coinbase: Transaction) -> Block {
        Block::new_block(vec![coinbase], String::new(), 0).unwrap()
    }

    /// Run performs a proof-of-work
    fn run_proof_of_work(&mut self) -> Result<()> {
        info!("Mining the block");
        while !self.validate()? {
            self.nonce += 1;
        }
        let data = self.prepare_hash_data()?;
        let mut hasher = Context::new(&SHA256);
        hasher.update(&data[..]);
        self.hash = hex::encode(hasher.finish().as_ref());
        Ok(())
    }

    /// HashTransactions returns a hash of the transactions in the block
    fn hash_transactions(&self) -> Result<Vec<u8>> {
        let mut transactions = Vec::new();
        for tx in &self.transactions {
            transactions.push(tx.hash()?.as_bytes().to_owned());
        }
        let tree = CBMT::<Vec<u8>, MergeVu8>::build_merkle_tree(transactions);

        Ok(tree.root())
    }

    fn prepare_hash_data(&self) -> Result<Vec<u8>> {
        let content = (
            self.prev_block_hash.clone(),
            self.hash_transactions()?,
            self.timestamp,
            TARGET_HEXS,
            self.nonce,
        );
        let bytes = serialize(&content)?;
        Ok(bytes)
    }

    /// Validate validates block's PoW
    fn validate(&self) -> Result<bool> {
        let data = self.prepare_hash_data()?;
        let mut hasher = Context::new(&SHA256);
        hasher.update(&data[..]);
        let hash_result = hasher.finish();
        let hash_hex = hex::encode(&hash_result.as_ref()[..TARGET_HEXS]); // 使用 hex crate 转换为十六进制字符串

        // 创建一个包含 TARGET_HEXS 个 '0' 的字符串进行比较
        let target_str = "0".repeat(TARGET_HEXS);

        // 比较哈希值与目标字符串是否相等
        Ok(&hash_hex == &target_str)
    }
}

struct MergeVu8 {}

impl Merge for MergeVu8 {
    type Item = Vec<u8>;
    fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
        let mut hasher = Context::new(&SHA256);
        let mut data: Vec<u8> = left.clone();
        data.append(&mut right.clone());
        hasher.update(&data);
        let re = hasher.finish();
        re.as_ref().to_vec()
    }
}
