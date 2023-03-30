use ark_std::{end_timer, start_timer};

use std::{
    collections::HashMap,
    env::current_dir,
    fs,
    path::{Path, PathBuf},
};

use circom::circuit::{CircomCircuit, R1CS};
use nova_snark::{
    traits::{circuit::TrivialTestCircuit, circuit::StepCircuit, Group},
    PublicParams, RecursiveSNARK,
};
use num_bigint::BigInt;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::circom::reader::generate_witness_from_bin;

#[cfg(not(target_family = "wasm"))]
use crate::circom::reader::generate_witness_from_wasm;

#[cfg(target_family = "wasm")]
use crate::circom::wasm::generate_witness_from_wasm;

pub mod circom;

pub type G1 = pasta_curves::pallas::Point;
pub type F1 = <G1 as Group>::Scalar;
pub type EE1 = nova_snark::provider::ipa_pc::EvaluationEngine<G1>;
pub type CC1 = nova_snark::spartan::spark::TrivialCompComputationEngine<G1, EE1>;
pub type S1 = nova_snark::spartan::RelaxedR1CSSNARK<G1, EE1, CC1>;
pub type G2 = pasta_curves::vesta::Point;
pub type F2 = <G2 as Group>::Scalar;
pub type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<G2>;
pub type CC2 = nova_snark::spartan::spark::TrivialCompComputationEngine<G2, EE2>;
pub type S2 = nova_snark::spartan::RelaxedR1CSSNARK<G2, EE2, CC2>;


type C1 = CircomCircuit<<G1 as Group>::Scalar>;
type C2 = CircomCircuit<<G2 as Group>::Scalar>;

// TODO: Figure out how to reconcile C2 and C2T
// StepCircuit is a trait
type C2T = TrivialTestCircuit<<G2 as Group>::Scalar>;


pub enum FileLocation {
    PathBuf(PathBuf),
    URL(String),
}

pub fn create_public_params(
    r1cs: R1CS<F1>,
) -> PublicParams<G1, G2, CircomCircuit<F1>, TrivialTestCircuit<F2>> {
    let circuit_primary = CircomCircuit {
        r1cs,
        witness: None,
    };
    let circuit_secondary = TrivialTestCircuit::default();

    let pp = PublicParams::<G1, G2, CircomCircuit<F1>, TrivialTestCircuit<F2>>::setup(
        circuit_primary.clone(),
        circuit_secondary.clone(),
    );
    pp
}

// Takes two R1CS instances
pub fn create_public_params_alt(
    r1cs_primary: R1CS<F1>,
    r1cs_secondary: R1CS<F2>,
) -> PublicParams<G1, G2, CircomCircuit<F1>, CircomCircuit<F2>> {
    let circuit_primary = CircomCircuit {
        r1cs: r1cs_primary,
        witness: None,
    };
    let circuit_secondary = CircomCircuit {
        r1cs: r1cs_secondary,
        witness: None,
    };

    let pp = PublicParams::<G1, G2, CircomCircuit<F1>, CircomCircuit<F2>>::setup(
        circuit_primary.clone(),
        circuit_secondary.clone(),
    );
    pp
}

#[derive(Serialize, Deserialize)]
struct CircomInput {
    step_in: Vec<String>,

    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

// TODO: Need to reconcile C2 and C2T above for this to work
//
// #[cfg(not(target_family = "wasm"))]
// pub fn create_recursive_circuit(
//     witness_generator_file: FileLocation,
//     r1cs: R1CS<F1>,
//     private_inputs: Vec<HashMap<String, Value>>,
//     start_public_input: Vec<F1>,
//     pp: &PublicParams<G1, G2, C1, C2>,
// ) -> Result<RecursiveSNARK<G1, G2, C1, C2>, std::io::Error>
// {
//     let root = current_dir().unwrap();
//     let witness_generator_output = root.join("circom_witness.wtns");

//     let iteration_count = private_inputs.len();

//     let start_public_input_hex = start_public_input
//         .iter()
//         .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
//         .collect::<Vec<String>>();
//     let mut current_public_input = start_public_input_hex.clone();

//     let circuit_secondary = TrivialTestCircuit::default();
//     let z0_secondary = vec![<G2 as Group>::Scalar::zero()];
//     let mut recursive_snark: Option<RecursiveSNARK<G1, G2, C1, C2>> = None;

//     for i in 0..iteration_count {
//         let decimal_stringified_input: Vec<String> = current_public_input
//             .iter()
//             .map(|x| BigInt::from_str_radix(x, 16).unwrap().to_str_radix(10))
//             .collect();

//         let input = CircomInput {
//             step_in: decimal_stringified_input.clone(),
//             extra: private_inputs[i].clone(),
//         };

//         let input_json = serde_json::to_string(&input).unwrap();

//         let is_wasm = match &witness_generator_file {
//             FileLocation::PathBuf(path) => path.extension().unwrap_or_default() == "wasm",
//             FileLocation::URL(_) => true,
//         };

//         let witness = if is_wasm {
//             generate_witness_from_wasm::<<G1 as Group>::Scalar>(
//                 &witness_generator_file,
//                 &input_json,
//                 &witness_generator_output,
//             )
//         } else {
//             let witness_generator_file = match &witness_generator_file {
//                 FileLocation::PathBuf(path) => path,
//                 FileLocation::URL(_) => panic!("unreachable"),
//             };
//             generate_witness_from_bin::<<G1 as Group>::Scalar>(
//                 &witness_generator_file,
//                 &input_json,
//                 &witness_generator_output,
//             )
//         };
//         let circuit = CircomCircuit {
//             r1cs: r1cs.clone(),
//             witness: Some(witness),
//         };

//         let current_public_output = circuit.get_public_outputs();
//         current_public_input = current_public_output
//             .iter()
//             .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
//             .collect();

//         // Prove step
//         // Also check inside prove_step
//         let timer_create_proof_steps = start_timer!(|| "Create recursive step proof");

//         let res = RecursiveSNARK::prove_step(
//             &pp,
//             recursive_snark,
//             circuit.clone(),
//             circuit_secondary.clone(),
//             start_public_input.clone(),
//             z0_secondary.clone(),
//         );
//         assert!(res.is_ok());
//         recursive_snark = Some(res.unwrap());

//         end_timer!(timer_create_proof_steps);

//     }

//     fs::remove_file(witness_generator_output)?;

//     let recursive_snark = recursive_snark.unwrap();
//     Ok(recursive_snark)
// }


// TODO Do wasm version too

#[cfg(not(target_family = "wasm"))]
pub fn create_recursive_circuit_alt(
    witness_generator_file: FileLocation,
    r1cs_primary: R1CS<F1>,
    r1cs_secondary: R1CS<F2>,
    // XXX private input same?
    private_inputs: Vec<HashMap<String, Value>>,
    start_public_input_primary: Vec<F1>,
    start_public_input_secondary: Vec<F2>,
    pp: &PublicParams<G1, G2, C1, C2>,
) -> Result<RecursiveSNARK<G1, G2, C1, C2>, std::io::Error> {
    let root = current_dir().unwrap();
    let witness_generator_output = root.join("circom_witness.wtns");

    let iteration_count = private_inputs.len();

    let start_public_input_hex_primary = start_public_input_primary
        .iter()
        .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
        .collect::<Vec<String>>();
    let mut current_public_input_primary = start_public_input_hex_primary.clone();

    let start_public_input_hex_secondary = start_public_input_secondary
        .iter()
        .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
        .collect::<Vec<String>>();
    let mut current_public_input_secondary = start_public_input_hex_secondary.clone();

    // This is what we had before
    //let circuit_secondary = TrivialTestCircuit::default();
    //let z0_secondary = vec![<G2 as Group>::Scalar::zero()];

    let mut recursive_snark: Option<RecursiveSNARK<G1, G2, C1, C2>> = None;

    for i in 0..iteration_count {
        let decimal_stringified_input_primary: Vec<String> = current_public_input_primary
            .iter()
            .map(|x| BigInt::from_str_radix(x, 16).unwrap().to_str_radix(10))
            .collect();

        // FIXME We ignore private input for now, this should be split or otherwise instrumented
        let input_primary = CircomInput {
            step_in: decimal_stringified_input_primary.clone(),
            extra: private_inputs[i].clone(),
        };

        let input_json_primary = serde_json::to_string(&input_primary).unwrap();

        let decimal_stringified_input_secondary: Vec<String> = current_public_input_secondary
        .iter()
        .map(|x| BigInt::from_str_radix(x, 16).unwrap().to_str_radix(10))
        .collect();

        let input_secondary = CircomInput {
            step_in: decimal_stringified_input_secondary.clone(),
            extra: private_inputs[i].clone(),
        };

        let input_json_secondary = serde_json::to_string(&input_secondary).unwrap();

        let is_wasm = match &witness_generator_file {
            FileLocation::PathBuf(path) => path.extension().unwrap_or_default() == "wasm",
            FileLocation::URL(_) => true,
        };

        let witness_primary = if is_wasm {
            generate_witness_from_wasm::<<G1 as Group>::Scalar>(
                &witness_generator_file,
                &input_json_primary,
                &witness_generator_output,
            )
        } else {
            let witness_generator_file = match &witness_generator_file {
                FileLocation::PathBuf(path) => path,
                FileLocation::URL(_) => panic!("unreachable"),
            };
            generate_witness_from_bin::<<G1 as Group>::Scalar>(
                &witness_generator_file,
                &input_json_primary,
                &witness_generator_output,
            )
        };

        // TODO Encapsulate better
        let witness_secondary = if is_wasm {
            generate_witness_from_wasm::<<G2 as Group>::Scalar>(
                &witness_generator_file,
                &input_json_secondary,
                &witness_generator_output,
            )
        } else {
            let witness_generator_file = match &witness_generator_file {
                FileLocation::PathBuf(path) => path,
                FileLocation::URL(_) => panic!("unreachable"),
            };
            generate_witness_from_bin::<<G2 as Group>::Scalar>(
                &witness_generator_file,
                &input_json_secondary,
                &witness_generator_output,
            )
        };

        let circuit_primary = CircomCircuit {
            r1cs: r1cs_primary.clone(),
            witness: Some(witness_primary),
        };

        let circuit_secondary = CircomCircuit {
            r1cs: r1cs_secondary.clone(),
            witness: Some(witness_secondary),
        };

        // TODO Make sure we get public output from other circuit too
        let current_public_output_primary = circuit_primary.get_public_outputs();
        current_public_input_primary = current_public_output_primary
            .iter()
            .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
            .collect();

        // Prove step
        let timer_create_proof_steps = start_timer!(|| "Create recursive step proof");
        let res = RecursiveSNARK::prove_step(
            &pp,
            recursive_snark,
            circuit_primary.clone(),
            circuit_secondary.clone(),
            start_public_input_primary.clone(),
            start_public_input_secondary.clone(),
        );
        assert!(res.is_ok());
        recursive_snark = Some(res.unwrap());

        end_timer!(timer_create_proof_steps);

    }

    fs::remove_file(witness_generator_output)?;

    let recursive_snark = recursive_snark.unwrap();
    Ok(recursive_snark)
}

#[cfg(target_family = "wasm")]
pub async fn create_recursive_circuit(
    witness_generator_file: FileLocation,
    r1cs: R1CS<F1>,
    private_inputs: Vec<HashMap<String, Value>>,
    start_public_input: Vec<F1>,
    pp: &PublicParams<G1, G2, C1, C2>,
) -> Result<RecursiveSNARK<G1, G2, C1, C2>, std::io::Error> {
    let iteration_count = private_inputs.len();
    let mut circuit_iterations = Vec::with_capacity(iteration_count);

    let start_public_input_hex = start_public_input
        .iter()
        .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
        .collect::<Vec<String>>();
    let mut current_public_input = start_public_input_hex.clone();

    for i in 0..iteration_count {
        let decimal_stringified_input: Vec<String> = current_public_input
            .iter()
            .map(|x| BigInt::from_str_radix(x, 16).unwrap().to_str_radix(10))
            .collect();

        let input = CircomInput {
            step_in: decimal_stringified_input.clone(),
            extra: private_inputs[i].clone(),
        };

        let input_json = serde_json::to_string(&input).unwrap();

        let is_wasm = match &witness_generator_file {
            FileLocation::PathBuf(path) => path.extension().unwrap_or_default() == "wasm",
            FileLocation::URL(_) => true,
        };

        let witness = if is_wasm {
            generate_witness_from_wasm::<<G1 as Group>::Scalar>(
                &witness_generator_file,
                &input_json,
                Path::new(""),
            )
            .await
        } else {
            let witness_generator_file = match &witness_generator_file {
                FileLocation::PathBuf(path) => path,
                FileLocation::URL(_) => panic!("unreachable"),
            };
            generate_witness_from_bin::<<G1 as Group>::Scalar>(
                &witness_generator_file,
                &input_json,
                Path::new(""),
            )
        };
        let circuit = CircomCircuit {
            r1cs: r1cs.clone(),
            witness: Some(witness),
        };
        let current_public_output = circuit.get_public_outputs();

        circuit_iterations.push(circuit);
        current_public_input = current_public_output
            .iter()
            .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
            .collect();
    }

    let circuit_secondary = TrivialTestCircuit::default();

    let mut recursive_snark: Option<RecursiveSNARK<G1, G2, C1, C2>> = None;

    let z0_secondary = vec![<G2 as Group>::Scalar::zero()];

    for i in 0..iteration_count {
        let res = RecursiveSNARK::prove_step(
            &pp,
            recursive_snark,
            circuit_iterations[i].clone(),
            circuit_secondary.clone(),
            start_public_input.clone(),
            z0_secondary.clone(),
        );

        assert!(res.is_ok());
        recursive_snark = Some(res.unwrap());
    }

    let recursive_snark = recursive_snark.unwrap();

    Ok(recursive_snark)
}
