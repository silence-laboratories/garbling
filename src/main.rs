// use std::{
//     collections::HashMap,
//     mem,
//     sync::{mpsc, Arc},
//     thread::{self, JoinHandle},
// };

use garbled_circuit::{
    circuitop::circuit::BinaryCircuit,
    circuitop::circuit_builder::CircuitBuilder,
    // config::constants::{Block, AES_KEY},
    // evaluator_operations::BinaryEvaluator,
    // garbler_operations::BinaryGarbler,
    garbling2pc::plaintext_operations::BinaryPlaintext,
    garbling3pc::threepartytraits::{
        ThreePartyBinaryCircuitBuilder,
        // ThreePartyBinaryCircuit, ThreePartyBinaryEvaluator,
        // ThreePartyBinaryGarbler, ThreePartyBinaryPlaintext,
    },
    // utilities::{
    //     commitments::{Commitment, HashCommitment},
    //     hash_function::AesHash,
    //     utils::xor_blocks,
    // },
};

// use rand::{rngs::ThreadRng, Rng, SeedableRng};
// use rand_chacha::ChaChaRng;

fn main() {
    let aescirc = BinaryCircuit::parse("circuits/aes256.txt");

    println!(
        "{} {} {} ",
        aescirc.evaluator_input_ids.len(),
        aescirc.garbler_input_ids.len(),
        aescirc.output_gate_ids.len()
    );

    let key = [false; 256].as_slice();
    let message = [false; 128].as_slice();

    // garbler input is key and evaluator input is ciphertext.
    let mut binplain = BinaryPlaintext::new();
    let mut output = binplain.evaluate(aescirc.clone(), key, message);
    output.reverse();

    let mut o1 = output.clone();

    o1.reverse();

    println!("{}", bool_vec_to_hex(o1));

    // let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY));
    // let (gen, een, gc, din) = garbler.garble(aescirc.clone()).unwrap();
    // let mut evaluator = BinaryEvaluator::new(gen.clone(), een.clone(), din.clone(), garbler.delta, AesHash::new(AES_KEY), gc.clone());
    // let output = evaluator.evaluate(aescirc.clone(), key, message).unwrap();
    // let decoutput = evaluator.get_plaintext_output(aescirc.get_output_gate_ids().to_vec(), output.clone());

    // let size_of_vec_struct = mem::size_of_val(&gc);
    // let size_of_elements = gc.len() * mem::size_of::<i32>();
    // let total_size = size_of_vec_struct + size_of_elements;
    // println!("Total size of Vec: {} bytes", total_size);

    // let mut o1 = decoutput.clone();

    // o1.reverse();

    // println!("{}", bool_vec_to_hex(o1));

    // // println!("\n\n\n");
    // // let circ2 = BinaryCircuit::parse_threeparty("circuits/aes128.txt");
    // let circ2 = build_comparison_circuit_threeparty();
    // for i in 0..2 {
    //     for j in 0..2 {
    //         let ibit1 = i%2 != 0;
    //         let jbit1 = j%2 != 0;
    //         let mut binplain = BinaryPlaintext::new();
    //         println!("grablen: {}", circ2.num_garbler_inputs());
    //         let output = binplain.evaluate_threeparty(circ2.clone(), [ibit1; 2].as_slice(), [[jbit1; 2].as_slice(), [false; 2].as_slice()]);
    //         println!("i: {} j: {} output: {:?}", i, j, output);
    //     }
    // }

    // let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY));
    // let (gen, een, gc, din) = garbler.garble_threeparty(circ2.clone()).unwrap();
    // for i in 0..2 {
    //     for j in 0..2 {
    //         let key = [i != 0; 2];
    //         let message = [j != 0; 2];

    //         let mut evaluator = BinaryEvaluator::new(gen.clone(), een.clone(), din.clone(), garbler.delta, AesHash::new(AES_KEY), gc.clone());
    //         let output = evaluator.evaluate_threeparty(circ2.clone(), &key, [&message, &[false; 2]]).unwrap();
    //         let decoutput = evaluator.get_plaintext_output(circ2.get_output_gate_ids().to_vec(), output.clone());
    //         println!("i: {} j: {} output: {:?}", i, j, decoutput)
    //     }
    // }

    // circ2.print_circuit();

    // for i in 0..2 {
    //     for j in 0..2 {
    //         let key = [i != 0; 128];
    //         let message = [j != 0; 128];
    //         let mut garbled_garbler_input = HashMap::new();
    //         for x in 0..circ2.num_garbler_inputs() {
    //             let mut bl = *gen.get(&x).unwrap();
    //             if key[x] {
    //                 bl = xor_blocks(bl, garbler.delta);
    //             }
    //             garbled_garbler_input.insert(x, bl);
    //         }

    //         let mut garbled_evaluator_input = HashMap::new();
    //         for x in 0..circ2.num_evaluator_inputs()/2 {
    //             let mut bl = *een.get(&(2*x)).unwrap();
    //             if message[x] {
    //                 bl = xor_blocks(bl, garbler.delta);
    //             }
    //             garbled_evaluator_input.insert(x, bl);
    //         }
    //         let mut garbled_evaluator_input2 = HashMap::new();
    //         for x in 0..circ2.num_evaluator_inputs()/2 {
    //             let bl = *een.get(&(2*x+1)).unwrap();
    //             // if message[x] {
    //             //     bl = xor_blocks(bl, garbler.delta);
    //             // }
    //             garbled_evaluator_input2.insert(x, bl);
    //         }
    //         let mut evaluator = BinaryEvaluator::new(gen.clone(), een.clone(), din.clone(), garbler.delta, AesHash::new(AES_KEY), gc.clone());
    //         let output = evaluator.garbled_evaluate_threeparty(circ2.clone(), garbled_garbler_input, [garbled_evaluator_input, garbled_evaluator_input2]).unwrap();
    //         let decoutput = evaluator.get_plaintext_output(circ2.get_output_gate_ids().to_vec(), output.clone());
    //         println!("i: {} j: {} output: {:?}", i, j, decoutput)
    //     }
    // }
}

pub fn build_comparison_circuit() -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let eval_input_1 = builder.evaluator_input();
    let garb_input_1 = builder.garbler_input();
    let eval_input_2 = builder.evaluator_input();
    let garb_input_2 = builder.garbler_input();

    // Compare the bits
    let eq0 = builder.xor(eval_input_1, garb_input_1);
    let eq1 = builder.xor(eval_input_2, garb_input_2);

    let onewire = builder.constant(1);
    let temp1 = builder.and(eq0, eq1);
    let temp2 = builder.xor(eq0, eq1);
    let before_not = builder.xor(temp1, temp2);
    let result = builder.xor(before_not, onewire);
    builder.output(result);

    builder.finish()
}

pub fn build_comparison_circuit_threeparty() -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let eval_input_1 = builder.evaluator_input_threeparty();
    let garb_input_1 = builder.garbler_input();
    let eval_input_2 = builder.evaluator_input_threeparty();
    let garb_input_2 = builder.garbler_input();

    // Compare the bits
    let eq0 = builder.xor(eval_input_1, garb_input_1);
    let eq1 = builder.xor(eval_input_2, garb_input_2);

    let onewire = builder.constant(1);
    let temp1 = builder.and(eq0, eq1);
    let temp2 = builder.xor(eq0, eq1);
    let before_not = builder.xor(temp1, temp2);
    let result = builder.xor(before_not, onewire);
    builder.output(result);

    builder.finish()
}

fn bool_vec_to_hex(vec: Vec<bool>) -> String {
    let mut hex_string = String::new();

    // Process the vector in chunks of 4 bits
    for chunk in vec.chunks(4) {
        let mut value = 0;

        // Convert each bit to its corresponding position in a nibble (4 bits)
        for (i, bit) in chunk.iter().enumerate() {
            if *bit {
                value |= 1 << (3 - i); // Shift bits according to position
            }
        }

        // Convert the 4-bit value to a hex digit
        hex_string.push_str(&format!("{:x}", value));
    }

    hex_string
}
