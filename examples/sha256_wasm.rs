use std::{collections::HashMap, env::current_dir, time::Instant};

use ff::PrimeField;
use ff::derive::bitvec::vec;
use nova_scotia::{
    circom::reader::load_r1cs, create_public_params, create_recursive_circuit, FileLocation, F1,
    G2, S1, S2,
};

use num_bigint::BigInt;
use num_traits::Num;
use nova_snark::{traits::Group, CompressedSNARK};
use serde::{Deserialize, Serialize};
use serde_json::json;

fn main() {
    let iteration_count = 5;
    let root = current_dir().unwrap();

    let circuit_file = root.join("examples/sha256/circom/sha256_test.r1cs");
    let r1cs = load_r1cs(&FileLocation::PathBuf(circuit_file));
    let witness_generator_wasm = root.join("examples/sha256/circom/sha256_test_js/sha256_test.wasm");

    let in_vector = vec![0; 32];
    let step_in_vector = vec![vec![0; 32], vec![102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8, 151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37]];

    let mut private_inputs = Vec::new();
    for _i in 0..iteration_count {
        let mut private_input = HashMap::new();
        private_input.insert("in".to_string(), json!(in_vector));
        private_inputs.push(private_input);
    }

    // TODO This should be different for each iteration
    println!("Private inputs: {:?}", private_inputs);

    // Why is format for private and public input different? This works eg
    // private_input.insert("hash".to_string(), json!(["245","165","253","66","209","106","32","48","39","152","239","110","211","9","151","155","67","0","61","35","32","217","240","232","234","152","49","169","39","89","251","75"]));
    // Currently input looks like:
    // input: "{\"step_in\":[\"17372487044184224250689677241555343188839180614373144612130640154373167982884\",\"195393092410815735158515771507856022968006678455652277576436
    // 44263387137250590\"],\"in\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"

    // TODO Fix this
    // For public input we want to have on form
    // F1::from_str_vartime(&btc_blocks.prevBlockHash[0]).unwrap(),
    // In circuit do we have to do use Num2Bits instead?
    let first_val_intstr = "46320509353513273106582423493727320152202237096314791991810382902766530930981";
    let second_val_intstr = "19539309241081573515851577150785602296800667845565227757643644263387137250590";

    let start_public_input = vec![
        F1::from_str_vartime(&first_val_intstr).unwrap(),
        F1::from_str_vartime(&second_val_intstr).unwrap(),
    ];

    let pp = create_public_params(r1cs.clone());

    println!(
        "Number of constraints per step (primary circuit): {}",
        pp.num_constraints().0
    );
    println!(
        "Number of constraints per step (secondary circuit): {}",
        pp.num_constraints().1
    );

    println!(
        "Number of variables per step (primary circuit): {}",
        pp.num_variables().0
    );
    println!(
        "Number of variables per step (secondary circuit): {}",
        pp.num_variables().1
    );

    println!("Creating a RecursiveSNARK...");
    let start = Instant::now();

    let recursive_snark = create_recursive_circuit(
        FileLocation::PathBuf(witness_generator_wasm),
        r1cs,
        private_inputs,
        start_public_input.clone(),
        &pp,
    )
    .unwrap();
    println!("RecursiveSNARK creation took {:?}", start.elapsed());

    // TODO: empty?
    let z0_secondary = vec![<G2 as Group>::Scalar::zero()];

    // verify the recursive SNARK
    println!("Verifying a RecursiveSNARK...");
    let start = Instant::now();
    let res = recursive_snark.verify(
        &pp,
        iteration_count,
        start_public_input.clone(),
        z0_secondary.clone(),
    );
    println!(
        "RecursiveSNARK::verify: {:?}, took {:?}",
        res,
        start.elapsed()
    );
    assert!(res.is_ok());

    // produce a compressed SNARK
    println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
    let start = Instant::now();
    let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &recursive_snark);
    println!(
        "CompressedSNARK::prove: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());
    let compressed_snark = res.unwrap();

    // verify the compressed SNARK
    println!("Verifying a CompressedSNARK...");
    let start = Instant::now();
    let res = compressed_snark.verify(
        &pp,
        iteration_count,
        start_public_input.clone(),
        z0_secondary,
    );
    println!(
        "CompressedSNARK::verify: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());
}
