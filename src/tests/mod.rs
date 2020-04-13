mod ckb_cell_upgrade;
mod key_bound_ownership_lock;
mod simple_otx;

use ckb_crypto::secp::{Privkey, Pubkey};
use ckb_fixed_hash::H512;
use ckb_script::DataLoader;
use ckb_types::{
    bytes::Bytes,
    core::{cell::CellMeta, BlockExt, EpochExt, HeaderView, TransactionView},
    packed::{self, Byte32, CellOutput, OutPoint, WitnessArgs},
    prelude::*,
    H256,
};
use secp256k1::key;

use lazy_static::lazy_static;
use std::collections::HashMap;

use sha3::{Digest, Keccak256};

pub const MAX_CYCLES: u64 = std::u64::MAX;
pub const SIGNATURE_SIZE: usize = 65;

lazy_static! {
    pub static ref SECP256K1_DATA_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/secp256k1_data")[..]);
    pub static ref KEY_BOUND_OWNERSHIP_LOCK_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/key_bound_ownership_lock")[..]);
    pub static ref SIMPLE_OTX_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/simple_otx")[..]);
    pub static ref CKB_CELL_UPGRADE_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/ckb_cell_upgrade")[..]);
    pub static ref SIGHASH_ALL_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/secp256k1_blake160_sighash_all")[..]);
}

#[derive(Default)]
pub struct DummyDataLoader {
    pub cells: HashMap<OutPoint, (CellOutput, Bytes)>,
    pub headers: HashMap<Byte32, HeaderView>,
    pub epoches: HashMap<Byte32, EpochExt>,
}

impl DummyDataLoader {
    fn new() -> Self {
        Self::default()
    }
}

impl DataLoader for DummyDataLoader {
    // load Cell Data
    fn load_cell_data(&self, cell: &CellMeta) -> Option<(Bytes, Byte32)> {
        cell.mem_cell_data.clone().or_else(|| {
            self.cells
                .get(&cell.out_point)
                .map(|(_, data)| (data.clone(), CellOutput::calc_data_hash(&data)))
        })
    }
    // load BlockExt
    fn get_block_ext(&self, _hash: &Byte32) -> Option<BlockExt> {
        unreachable!()
    }

    // load header
    fn get_header(&self, block_hash: &Byte32) -> Option<HeaderView> {
        self.headers.get(block_hash).cloned()
    }

    // load EpochExt
    fn get_block_epoch(&self, block_hash: &Byte32) -> Option<EpochExt> {
        self.epoches.get(block_hash).cloned()
    }
}

// pub fn eth160(message: &[u8]) -> Bytes {
pub fn eth160(pubkey1: Pubkey) -> Bytes {
    let prefix_key: [u8; 65] = {
        let mut temp = [4u8; 65];
        let h512: H512 = pubkey1.into();
        temp[1..65].copy_from_slice(h512.as_bytes());
        temp
    };
    let pubkey = key::PublicKey::from_slice(&prefix_key).unwrap();
    let message = Vec::from(&pubkey.serialize_uncompressed()[1..]);
    // let message = Vec::from(&pubkey.serialize()[..]);

    // println!("{}", faster_hex::hex_string(&message).unwrap());
    // println!("{}", faster_hex::hex_string(&message1).unwrap());

    let mut hasher = Keccak256::default();
    hasher.input(&message);
    Bytes::from(hasher.result().as_slice()).slice(12, 32)
}

pub fn sign_tx(tx: TransactionView, key: &Privkey) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    sign_tx_by_input_group(tx, key, 0, witnesses_len)
}

pub fn sign_tx_by_input_group(
    tx: TransactionView,
    key: &Privkey,
    begin_index: usize,
    len: usize,
) -> TransactionView {
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            if i == begin_index {
                let mut blake2b = ckb_hash::new_blake2b();
                let mut message = [0u8; 32];
                blake2b.update(&tx_hash.raw_data());
                // digest the first witness
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.resize(SIGNATURE_SIZE, 0);
                    buf.into()
                };
                let witness_for_digest =
                    witness.clone().as_builder().lock(zero_lock.pack()).build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                blake2b.update(&witness_len.to_le_bytes());
                blake2b.update(&witness_for_digest.as_bytes());
                ((i + 1)..(i + len)).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    let witness_len = witness.raw_data().len() as u64;
                    blake2b.update(&witness_len.to_le_bytes());
                    blake2b.update(&witness.raw_data());
                });
                blake2b.finalize(&mut message);
                let message = H256::from(message);
                let sig = key.sign_recoverable(&message).expect("sign");
                witness
                    .as_builder()
                    .lock(sig.serialize().pack())
                    .build()
                    .as_bytes()
                    .pack()
            } else {
                tx.witnesses().get(i).unwrap_or_default()
            }
        })
        .collect();
    for i in signed_witnesses.len()..tx.witnesses().len() {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

pub fn sign_simple_otx(tx: TransactionView, key: &Privkey) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    sign_simple_otx_by_input_group(tx, key, 0, witnesses_len)
}

pub fn sign_simple_otx_by_input_group(
    tx: TransactionView,
    key: &Privkey,
    begin_index: usize,
    len: usize,
) -> TransactionView {
    let simple_otx_hash = get_simple_otx_hash(&tx, begin_index, len);

    println!("simple_otx_hash = {:?}", simple_otx_hash);

    let mut signed_witnesses: Vec<packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            if i == begin_index {
                let mut hasher = Keccak256::default();
                let mut message = [0u8; 32];

                hasher.input(&simple_otx_hash);

                // digest the first witness
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.resize(SIGNATURE_SIZE, 0);
                    buf.into()
                };
                let witness_for_digest =
                    witness.clone().as_builder().lock(zero_lock.pack()).build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                hasher.input(&witness_len.to_le_bytes());
                hasher.input(&witness_for_digest.as_bytes());
                ((i + 1)..(i + len)).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    let witness_len = witness.raw_data().len() as u64;
                    hasher.input(&witness_len.to_le_bytes());
                    hasher.input(&witness.raw_data());
                });

                message.copy_from_slice(&hasher.result()[0..32]);

                let prefix: [u8; 28] = [
                    0x19, 0x45, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x20, 0x53, 0x69, 0x67,
                    0x6e, 0x65, 0x64, 0x20, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x3a, 0x0a,
                    0x33, 0x32,
                ];
                hasher = Keccak256::default();
                hasher.input(&prefix);
                hasher.input(&message);
                message.copy_from_slice(&hasher.result()[0..32]);

                println!("simple otx personal hash is {:?}", message);
                let message = H256::from(message);
                let sig = key.sign_recoverable(&message).expect("sign");
                witness
                    .as_builder()
                    .lock(sig.serialize().pack())
                    .build()
                    .as_bytes()
                    .pack()
            } else {
                tx.witnesses().get(i).unwrap_or_default()
            }
        })
        .collect();
    for i in signed_witnesses.len()..tx.witnesses().len() {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

pub fn get_simple_otx_hash(tx: &TransactionView, begin_index: usize, len: usize) -> [u8; 32] {
    let mut hasher = Keccak256::default();
    let mut simple_otx_hash = [0u8; 32];

    for i in 0..len {
        let index = begin_index + i;

        println!("index {}", index);

        hasher.input(&tx.inputs().get(index).unwrap().as_bytes());
        println!("input is {:?}", tx.inputs().get(index).unwrap().as_bytes());

        let output = tx.output(index).unwrap();
        // output cell capacity
        println!("capacity is {:?}", output.capacity().as_bytes());
        hasher.input(&output.capacity().as_bytes());
        // output cell lock script hash
        let lock_hash = output.calc_lock_hash();
        println!("lock_hash is {}", lock_hash);
        hasher.input(&lock_hash.as_bytes());
        // output cell type script hash
        let type_hash = match output.type_().to_opt() {
            Some(v) => v.calc_script_hash(),
            None => Byte32::zero(),
        };
        println!("type_hash is {}", type_hash);
        hasher.input(&type_hash.as_bytes());
        // output cell data hash
        let data_hash = match tx.outputs_data().get(index) {
            Some(v) => CellOutput::calc_data_hash(&v.raw_data()),
            None => Byte32::zero(),
        };
        println!("data_hash is {}", data_hash);
        hasher.input(&data_hash.as_bytes());
    }

    simple_otx_hash.copy_from_slice(&hasher.result()[0..32]);
    simple_otx_hash
}
