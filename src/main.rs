
use std::mem;

use circuit::BinaryCircuit;
use config::constants::AES_KEY;
use evaluator_operations::BinaryEvaluator;
use garbler_operations::BinaryGarbler;
use hash_function::AesHash;
use plaintext_operations::BinaryPlaintext;
use threepartytraits::{ThreePartyBinaryCircuit, ThreePartyBinaryEvaluator, ThreePartyBinaryGarbler, ThreePartyBinaryPlaintext};

mod config;
mod hash_function;
pub mod circuit;
pub mod exec;
pub mod plaintext_operations;
mod garbler_operations;
mod evaluator_operations;
pub mod utils;
pub mod commitments;
pub mod threepartytraits;
pub mod circuit_builder;
pub mod gate;
pub mod communication;

fn main() {
    let aescirc = BinaryCircuit::parse("aes128.txt");

    println!("{} {} {} ", aescirc.evaluator_input_ids.len(), aescirc.garbler_input_ids.len(), aescirc.output_gate_ids.len());

    let key = [false; 128].as_slice();
    let message = [false; 128].as_slice();

    // garbler input is key and evaluator input is ciphertext.
    let mut binplain = BinaryPlaintext::new();
    let output = binplain.evaluate(aescirc.clone(), key, message);

    let mut o1 = output.clone();

    o1.reverse();

    println!("{}", bool_vec_to_hex(o1));

    let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY));    
    let (gen, een, gc, din) = garbler.garble(aescirc.clone()).unwrap();
    let mut evaluator = BinaryEvaluator::new(gen.clone(), een.clone(), din.clone(), garbler.delta, AesHash::new(AES_KEY), gc.clone());
    let output = evaluator.evaluate(aescirc.clone(), key, message).unwrap();
    let decoutput = evaluator.get_plaintext_output(aescirc.get_output_gate_ids().to_vec(), output.clone());

    let size_of_vec_struct = mem::size_of_val(&gc);
    let size_of_elements = gc.len() * mem::size_of::<i32>();
    let total_size = size_of_vec_struct + size_of_elements;
    println!("Total size of Vec: {} bytes", total_size);
    
    let mut o1 = decoutput.clone();

    o1.reverse();

    println!("{}", bool_vec_to_hex(o1));

    // println!("\n\n\n");
    let circ2 = BinaryCircuit::parse_threeparty("aes128.txt");
    for i in 0..2 {
        for j in 0..2 {
            let ibit1 = i%2 != 0;
            let jbit1 = j%2 != 0;
            let mut binplain = BinaryPlaintext::new();
            let output = binplain.evaluate_threeparty(circ2.clone(), [ibit1; 128].as_slice(), [[jbit1; 128].as_slice(), [false; 128].as_slice()]);
            println!("i: {} j: {} output: {:?}", i, j, bool_vec_to_hex(output));
        }
    }

    let mut garbler = BinaryGarbler::new(AesHash::new(AES_KEY));
    let (gen, een, gc, din) = garbler.garble_threeparty(circ2.clone()).unwrap();
    for i in 0..2 {
        for j in 0..2 {
            let key = [i != 0; 128];
            let message = [j != 0; 128];
            
            let mut evaluator = BinaryEvaluator::new(gen.clone(), een.clone(), din.clone(), garbler.delta, AesHash::new(AES_KEY), gc.clone());
            let output = evaluator.evaluate_threeparty(circ2.clone(), &key, [&message, &[false; 128]]).unwrap();
            let decoutput = evaluator.get_plaintext_output(circ2.get_output_gate_ids().to_vec(), output.clone());
            println!("i: {} j: {} output: {:?}", i, j, bool_vec_to_hex(decoutput))
        }
    }
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