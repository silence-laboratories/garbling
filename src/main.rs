
use std::mem;

use circuit::BinaryCircuit;
use config::constants::AES_KEY;
use evaluator_operations::BinaryEvaluator;
use hash_aes::AesHash;

mod config;
mod hash_aes;
pub mod circuit;
mod errors;
pub mod exec;
pub mod plaintext_operations;
mod garbler_operations;
mod evaluator_operations;
pub mod utils;

fn main() {
    let aescirc = BinaryCircuit::parse("aes128.txt");

    println!("{} {} {} ", aescirc.evaluator_input_ids.len(), aescirc.garbler_input_ids.len(), aescirc.output_gate_ids.len());

    let key = [false; 128].as_slice();
    let message = [false; 128].as_slice();

    // garbler input is key and evaluator input is ciphertext.
    let output = aescirc.evaluate_plaintext( key, message);

    let mut o1 = output.clone();

    o1.reverse();

    println!("{}", bool_vec_to_hex(o1));
    
    let (gen, een, gc, din, delta) = aescirc.garble(AesHash::new(AES_KEY));
    let mut evaluator = BinaryEvaluator::new(gen.clone(), een.clone(), din.clone(), delta, AesHash::new(AES_KEY), gc.clone());
    let output = aescirc.evaluator_evaluate(&mut evaluator, key, message).unwrap();
    let decoutput = evaluator.get_plaintext_output(aescirc.get_output_gate_ids().to_vec(), output.clone());

    let size_of_vec_struct = mem::size_of_val(&gc);
    let size_of_elements = gc.len() * mem::size_of::<i32>();
    let total_size = size_of_vec_struct + size_of_elements;
    println!("Total size of Vec: {} bytes", total_size);
    
    let mut o1 = decoutput.clone();

    o1.reverse();

    println!("{}", bool_vec_to_hex(o1));
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