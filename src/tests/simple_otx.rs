use super::{
    eth160, sign_simple_otx, sign_simple_otx_by_input_group, DummyDataLoader, CKB_CELL_UPGRADE_BIN,
    MAX_CYCLES, SECP256K1_DATA_BIN, SIGHASH_ALL_BIN, SIMPLE_OTX_BIN,
};
use ckb_crypto::secp::Generator;
use ckb_error::assert_error_eq;
use ckb_script::{ScriptError, TransactionScriptsVerifier};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellMetaBuilder, ResolvedTransaction},
        Capacity, DepType, ScriptHashType, TransactionBuilder, TransactionView,
    },
    packed::{Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgsBuilder},
    prelude::*,
};
use rand::{thread_rng, Rng};

fn script_cell(script_data: &Bytes) -> (CellOutput, OutPoint) {
    let out_point = generate_random_out_point();

    let cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(script_data.len())
                .expect("script capacity")
                .pack(),
        )
        .build();

    (cell, out_point)
}

fn simple_otx_code_hash() -> Byte32 {
    CellOutput::calc_data_hash(&SIMPLE_OTX_BIN)
}

fn generate_random_out_point() -> OutPoint {
    let tx_hash = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        buf.pack()
    };
    OutPoint::new(tx_hash, 0)
}

fn dummy_cell_output(shannons: u64) -> CellOutput {
    CellOutput::new_builder()
        .capacity(Capacity::shannons(shannons).pack())
        .build()
}

fn gen_simple_otx_cell(
    dummy: &mut DummyDataLoader,
    capacity: Capacity,
    lock_args: Bytes,
    data: Bytes,
) -> (CellOutput, OutPoint) {
    let out_point = generate_random_out_point();

    let lock = Script::new_builder()
        .args(lock_args.pack())
        .code_hash(simple_otx_code_hash())
        .hash_type(ScriptHashType::Data.into())
        .build();
    // let type_ = Script::new_builder()
    //     .args(Bytes::new().pack())
    //     .code_hash(upgrade_code_hash())
    //     .hash_type(ScriptHashType::Data.into())
    //     .build();

    let cell = CellOutput::new_builder()
        .capacity(capacity.pack())
        .lock(lock)
        // .type_(Some(type_).pack())
        .build();

    dummy.cells.insert(out_point.clone(), (cell.clone(), data));

    (cell, out_point)
}

fn complete_tx(
    dummy: &mut DummyDataLoader,
    builder: TransactionBuilder,
) -> (TransactionView, Vec<CellMeta>) {
    let (secp_cell, secp_out_point) = script_cell(&SIGHASH_ALL_BIN);
    let (secp_data_cell, secp_data_out_point) = script_cell(&SECP256K1_DATA_BIN);
    let (upgrade_cell, upgrade_out_point) = script_cell(&CKB_CELL_UPGRADE_BIN);
    let (simple_otx_cell, simple_otx_out_point) = script_cell(&SIMPLE_OTX_BIN);

    let secp_cell_meta =
        CellMetaBuilder::from_cell_output(secp_cell.clone(), SIGHASH_ALL_BIN.clone())
            .out_point(secp_out_point.clone())
            .build();
    let secp_data_cell_meta =
        CellMetaBuilder::from_cell_output(secp_data_cell.clone(), SECP256K1_DATA_BIN.clone())
            .out_point(secp_data_out_point.clone())
            .build();
    let upgrade_cell_meta =
        CellMetaBuilder::from_cell_output(upgrade_cell.clone(), CKB_CELL_UPGRADE_BIN.clone())
            .out_point(upgrade_out_point.clone())
            .build();
    let simple_otx_cell_meta =
        CellMetaBuilder::from_cell_output(simple_otx_cell.clone(), SIMPLE_OTX_BIN.clone())
            .out_point(simple_otx_out_point.clone())
            .build();

    dummy
        .cells
        .insert(secp_out_point.clone(), (secp_cell, SIGHASH_ALL_BIN.clone()));
    dummy.cells.insert(
        secp_data_out_point.clone(),
        (secp_data_cell, SECP256K1_DATA_BIN.clone()),
    );
    dummy.cells.insert(
        upgrade_out_point.clone(),
        (upgrade_cell, CKB_CELL_UPGRADE_BIN.clone()),
    );

    dummy.cells.insert(
        simple_otx_out_point.clone(),
        (simple_otx_cell, SIMPLE_OTX_BIN.clone()),
    );

    let tx = builder
        .cell_dep(
            CellDep::new_builder()
                .out_point(secp_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(secp_data_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(upgrade_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(simple_otx_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .build();

    let mut resolved_cell_deps = vec![];
    resolved_cell_deps.push(secp_cell_meta);
    resolved_cell_deps.push(secp_data_cell_meta);
    resolved_cell_deps.push(upgrade_cell_meta);
    resolved_cell_deps.push(simple_otx_cell_meta);

    (tx, resolved_cell_deps)
}

#[test]
fn test_simple_otx_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = eth160(pubkey);

    let (cell, previous_out_point) = gen_simple_otx_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        pubkey_hash,
        Bytes::from("hello world"),
    );

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from("hello world"))
        .out_point(previous_out_point.clone())
        .build();
    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut random_extra_witness = [0u8; 32];
    let mut rng = thread_rng();
    rng.fill(&mut random_extra_witness);
    let witness_args = WitnessArgsBuilder::default()
        .extra(Bytes::from(random_extra_witness.to_vec()).pack())
        .build();

    let output_data = Bytes::from("hello world 1").pack();
    println!("output_data is {}", output_data);
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e8022a0002f3))
        .output(dummy_cell_output(123456780000))
        .output_data(output_data)
        .witness(witness_args.as_bytes().pack());

    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_simple_otx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
    // assert_error_eq!(
    //     verify_result.unwrap_err(),
    //     ScriptError::ValidationFailure(-31),
    // );
}

#[test]
fn test_simple_otx_unbalanced() {}

#[test]
fn test_simple_otx_with_two_keys() {
    let mut data_loader = DummyDataLoader::new();

    //key1
    let privkey1 = Generator::random_privkey();
    let pubkey1 = privkey1.pubkey().expect("pubkey");
    let pubkey_hash1 = eth160(pubkey1);

    //key2
    let privkey2 = Generator::random_privkey();
    let pubkey2 = privkey2.pubkey().expect("pubkey");
    let pubkey_hash2 = eth160(pubkey2);

    let (cell1, previous_out_point1) = gen_simple_otx_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        pubkey_hash1,
        Bytes::from("hello world"),
    );

    let (cell2, previous_out_point2) = gen_simple_otx_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        pubkey_hash2,
        Bytes::from("hello world"),
    );

    let input_cell_meta1 = CellMetaBuilder::from_cell_output(cell1, Bytes::from("hello world"))
        .out_point(previous_out_point1.clone())
        .build();

    let input_cell_meta2 = CellMetaBuilder::from_cell_output(cell2, Bytes::from("hello world"))
        .out_point(previous_out_point2.clone())
        .build();
    let resolved_inputs = vec![input_cell_meta1, input_cell_meta2];
    let mut resolved_cell_deps = vec![];

    let mut random_extra_witness = [0u8; 32];
    let mut rng = thread_rng();
    rng.fill(&mut random_extra_witness);
    let witness_args = WitnessArgsBuilder::default()
        .extra(Bytes::from(random_extra_witness.to_vec()).pack())
        .build();

    let output_data1 = Bytes::from("hello world 1").pack();
    let output_data2 = Bytes::from("hello world 1").pack();
    println!("output_data is {}", output_data1);
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point1, 0x2003e8022a0002f3))
        .input(CellInput::new(previous_out_point2, 0x2003e8022a0002f3))
        .output(dummy_cell_output(123456780000))
        .output(dummy_cell_output(123456780000))
        .output_data(output_data1)
        .output_data(output_data2)
        .witness(witness_args.as_bytes().pack())
        .witness(witness_args.as_bytes().pack());

    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_simple_otx_by_input_group(tx, &privkey1, 0, 1);
    let tx = sign_simple_otx_by_input_group(tx, &privkey2, 1, 1);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_simple_otx_for() {
    let privkey2 = Generator::random_privkey();

    let tx_hash: Vec<u8> = vec![
        0xbc, 0xd3, 0x21, 0xac, 0x06, 0xf9, 0xc7, 0x10, 0x77, 0x49, 0x89, 0x16, 0x21, 0x5b, 0x40,
        0x4e, 0xfb, 0x4d, 0x09, 0xcc, 0x11, 0xa6, 0xcf, 0x5b, 0xb3, 0xb7, 0x69, 0xc8, 0x8b, 0x58,
        0x7f, 0x81,
    ];

    let outpoint = OutPoint::new(Byte32::new_unchecked(tx_hash.into()), 0);

    let code_hash: Vec<u8> = vec![
        0x9b, 0xd7, 0xe0, 0x6f, 0x3e, 0xcf, 0x4b, 0xe0, 0xf2, 0xfc, 0xd2, 0x18, 0x8b, 0x23, 0xf1,
        0xb9, 0xfc, 0xc8, 0x8e, 0x5d, 0x4b, 0x65, 0xa8, 0x63, 0x7b, 0x17, 0x72, 0x3b, 0xbd, 0xa3,
        0xcc, 0xe8,
    ];

    let args: [u8; 20] = [
        0xca, 0x91, 0x1d, 0x88, 0x50, 0xe5, 0x5c, 0xaa, 0xbe, 0x27, 0xc1, 0xfb, 0xf9, 0x0b, 0x52,
        0x2d, 0xb1, 0x07, 0x74, 0xbc,
    ];

    let args_param: Bytes = args.to_vec().into();

    let lock = Script::new_builder()
        .code_hash(Byte32::new_unchecked(code_hash.into()))
        .hash_type(ScriptHashType::Type.into())
        .args(args_param.pack())
        .build();

    let output = CellOutput::new_builder()
        .capacity(Capacity::shannons(0x2540be400).pack())
        .lock(lock)
        .build();

    let tx = TransactionBuilder::default()
        .input(CellInput::new(outpoint, 0x0))
        .output(output)
        .output_data(Bytes::new().pack())
        .build();

    sign_simple_otx_by_input_group(tx, &privkey2, 0, 1);
}
