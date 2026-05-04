use sl_compute_common::BinaryString;
use zcash::{blake2b::create_blake2b_circuit, eval::evaluate};

fn main() {
    let ip_len = 1024 + 128;
    let circ = create_blake2b_circuit(ip_len);
    let out = evaluate(&circ, &[&vec![true; ip_len]]);

    let mut x = BinaryString::new();
    let mut y = Vec::new();
    for i in out {
        x.push(i);
        y.push(if i { 1 } else { 0 });
    }
    println!("{y:?}");
    println!("{}", hex::encode(&x.value));
}
