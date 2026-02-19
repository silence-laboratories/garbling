use garbled_circuit::circuitop::{circuit::BinaryCircuit, gate::BinaryGate};

pub fn evaluate(circuit: &BinaryCircuit, inputs: &[&[bool]]) -> Vec<bool> {
    let mut w = vec![false; circuit.gates.len()];

    for gate in circuit.gates.iter() {
        let (out_gate, f_label) = match *gate {
            BinaryGate::Input { no, id, wire } => {
                let share = inputs[no as usize][id as usize];
                (wire, share)
            }

            BinaryGate::Constant { val, wire } => (wire, val != 0),

            BinaryGate::Xor { xid, yid, out } => {
                let x_label = &w[xid as usize];
                let y_label = &w[yid as usize];
                (out, x_label ^ y_label)
            }

            BinaryGate::And {
                xid,
                yid,
                id: _,
                out,
            } => {
                let x_label = &w[xid as usize];
                let y_label = &w[yid as usize];
                (out, x_label & y_label)
            }

            BinaryGate::Inv { xid, out } => {
                let x_label = &w[xid as usize];
                (out, !x_label)
            }
        };

        w[out_gate as usize] = f_label;
    }

    let mut outputs = Vec::new();
    for &r in circuit.get_output_gate_ids() {
        let out = w[r as usize];
        outputs.push(out);
    }

    outputs
}

#[cfg(test)]
mod tests {
    use garbled_circuit::{
        circuitop::circuit::BinaryCircuit, utilities::utils::bool_vec_to_hex,
    };

    use crate::eval::evaluate;

    #[test]
    fn test_aes_eval() {
        pub const AES128_CIRCUIT: &str =
            include_str!("../../../circuits/aes128.txt");
        let circuit = BinaryCircuit::parse(AES128_CIRCUIT).unwrap();
        for i in 0..2 {
            for j in 0..2 {
                let output =
                    evaluate(&circuit, &[&[i != 0; 128], &[j != 0; 128]]);
                let count = 2 * i + j;
                let hexout = bool_vec_to_hex(output);
                if count == 0 {
                    assert_eq!(
                        hexout,
                        "74d42c539a5f3211dc3451f72bd29766".to_string(),
                        "outval: {hexout} realval: 74d42c539a5f3211dc3451f72bd29766"
                    );
                } else if count == 2 {
                    assert_eq!(
                        hexout,
                        "3493fd1ca2122691b3fabee131a46f85".to_string(),
                        "outval: {hexout} realval: 3493fd1ca2122691b3fabee131a46f85"
                    );
                } else if count == 1 {
                    assert_eq!(
                        hexout,
                        "7266b17c4be2ce5f505aa1579331dafc".to_string(),
                        "outval: {hexout} realval: 7266b17c4be2ce5f505aa1579331dafc"
                    );
                } else if count == 3 {
                    assert_eq!(
                        hexout,
                        "9e9d5c984a0e8a4d0cf3014d3e84fd3d".to_string(),
                        "outval: {hexout} realval: 9e9d5c984a0e8a4d0cf3014d3e84fd3d"
                    );
                }
            }
        }
    }
}
