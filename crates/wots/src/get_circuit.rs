use std::collections::{HashMap, HashSet};

use garbled_circuit::circuitop::{circuit::BinaryCircuit, gate::BinaryGate};

pub fn get_bristol_fashion(circuit: &BinaryCircuit) -> String {
    let mut wire_map: HashMap<u32, u32> = HashMap::new();
    let mut next_wire: u32 = 0;

    let mut gate_lines = Vec::new();

    let mut done_consts = HashSet::new();
    let mut total_wire = 0;
    let mut total_gate = 0;
    let num_outputs = circuit.output_gate_ids.len();

    let mut any_input_wire = 0;

    for gate in &circuit.gates {
        match gate {
            BinaryGate::Input { no: _, id: _, wire } => {
                wire_map.insert(*wire, next_wire);
                any_input_wire = next_wire;
                next_wire += 1;
                total_wire += 1;
            }
            BinaryGate::Constant { val: _, wire: _ } => {}
            BinaryGate::Xor {
                xid: _,
                yid: _,
                out: _,
            } => {
                total_wire += 1;
                total_gate += 1;
            }
            BinaryGate::And {
                xid: _,
                yid: _,
                id: _,
                out: _,
            } => {
                total_wire += 1;
                total_gate += 1;
            }
            BinaryGate::Inv { xid: _, out: _ } => {
                total_wire += 1;
                total_gate += 1;
            }
        }
    }

    if circuit.constant_map.len() == 2 {
        total_wire += 2;
        total_gate += 2;
    } else if circuit.constant_map.contains_key(&0) {
        total_wire += 1;
        total_gate += 1;
    } else if circuit.constant_map.contains_key(&1) {
        total_wire += 2;
        total_gate += 2;
    }

    for gate in &circuit.gates {
        match gate {
            BinaryGate::Input {
                no: _,
                id: _,
                wire: _,
            } => {}
            BinaryGate::Constant { val, wire: _ } => {
                if *val == 0 {
                    if done_consts.contains(&1) {
                    } else {
                        gate_lines.push(format!(
                            "2 1 {any_input_wire} {any_input_wire} {next_wire} XOR"
                        ));
                        wire_map.insert(
                            *circuit.constant_map.get(val).unwrap(),
                            next_wire,
                        );
                        next_wire += 1;

                        done_consts.insert(0);
                    }
                } else if done_consts.contains(&0) {
                    gate_lines.push(format!(
                        "1 1 {} {} INV",
                        wire_map[&circuit.constant_map[&0]], next_wire
                    ));
                    wire_map.insert(
                        *circuit.constant_map.get(val).unwrap(),
                        next_wire,
                    );
                    next_wire += 1;
                    done_consts.insert(1);
                } else {
                    gate_lines.push(format!(
                        "2 1 {any_input_wire} {any_input_wire} {next_wire} XOR"
                    ));
                    if circuit.constant_map.contains_key(&0) {
                        wire_map.insert(
                            *circuit.constant_map.get(&0).unwrap(),
                            next_wire,
                        );
                    }
                    next_wire += 1;
                    done_consts.insert(0);

                    gate_lines.push(format!(
                        "1 1 {} {} INV",
                        next_wire - 1,
                        next_wire
                    ));
                    wire_map.insert(
                        *circuit.constant_map.get(val).unwrap(),
                        next_wire,
                    );
                    next_wire += 1;
                    done_consts.insert(1);
                }
            }
            BinaryGate::Xor { xid, yid, out } => {
                let out_wire = if let Some(index) =
                    circuit.output_gate_ids.iter().position(|&x| x == *out)
                {
                    let outwire = total_wire - num_outputs + index;
                    outwire as u32
                } else {
                    next_wire += 1;
                    next_wire - 1
                };
                wire_map.insert(*out, out_wire);
                gate_lines.push(format!(
                    "2 1 {} {} {} XOR",
                    wire_map[xid], wire_map[yid], out_wire
                ));
            }
            BinaryGate::And {
                xid,
                yid,
                id: _,
                out,
            } => {
                let out_wire = if let Some(index) =
                    circuit.output_gate_ids.iter().position(|&x| x == *out)
                {
                    let outwire = total_wire - num_outputs + index;
                    outwire as u32
                } else {
                    next_wire += 1;
                    next_wire - 1
                };
                wire_map.insert(*out, out_wire);
                gate_lines.push(format!(
                    "2 1 {} {} {} AND",
                    wire_map[xid], wire_map[yid], out_wire
                ));
            }
            BinaryGate::Inv { xid, out } => {
                let out_wire = if let Some(index) =
                    circuit.output_gate_ids.iter().position(|&x| x == *out)
                {
                    let outwire = total_wire - num_outputs + index;
                    outwire as u32
                } else {
                    next_wire += 1;
                    next_wire - 1
                };
                wire_map.insert(*out, out_wire);
                gate_lines
                    .push(format!("1 1 {} {} INV", wire_map[xid], out_wire));
            }
        }
    }

    let mut out = String::new();

    out.push_str(&format!("{total_gate} {total_wire}\n"));

    out.push_str(&format!("{}", circuit.input_gate_ids.len()));
    for group in &circuit.input_gate_ids {
        out.push_str(&format!(" {}", group.len()));
    }
    out.push('\n');
    out.push_str(&format!("1 {}\n", circuit.output_gate_ids.len()));

    for i in &gate_lines {
        out.push_str(i);
        out.push('\n');
    }

    out
}

#[cfg(test)]
mod tests {
    use garbled_circuit::{
        circuitop::circuit::BinaryCircuit,
        config::constants::{AES128_CIRCUIT, BINMULT_CIRCUIT},
        customcircuits::comparison::build_comparison_circuit,
    };
    use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};

    use crate::{
        chain::binstr_to_boolvec, eval::evaluate,
        expand_seed::build_expand_seed_circuit,
        get_circuit::get_bristol_fashion, pk_gen::build_pk_gen_circuit,
        sha_256::build_sha256_circuit, sign::build_sign_circuit,
        utils::u8_vec_to_binary_string,
    };

    #[test]
    fn test_get_circuit_1() {
        let circuit1 = BinaryCircuit::parse(BINMULT_CIRCUIT).unwrap();

        let obtained = get_bristol_fashion(&circuit1);

        let circuit2 = BinaryCircuit::parse(&obtained).unwrap();

        let mut rng = StdRng::from_entropy();
        for _ in 0..20 {
            let mut val: u8 = rng.r#gen();
            let ip1 = val % 2 != 0;
            val /= 2;
            let ip2 = val % 2 != 0;
            val /= 2;
            let ip3 = val % 2 != 0;
            val /= 2;
            let ip4 = val % 2 != 0;

            let op1 = evaluate(&circuit1, &[&[ip1, ip2], &[ip3, ip4]]);
            let op2 = evaluate(&circuit2, &[&[ip1, ip2], &[ip3, ip4]]);

            assert_eq!(op1, op2);
        }
    }

    #[test]
    fn test_get_circuit_2() {
        let circuit1 = build_comparison_circuit();

        circuit1.print_circuit();

        let obtained = get_bristol_fashion(&circuit1);

        println!("OBTAINED: {obtained}");

        let circuit2 = BinaryCircuit::parse(&obtained).unwrap();

        let mut rng = StdRng::from_entropy();
        for _ in 0..20 {
            let mut val: u8 = rng.r#gen();
            let ip1 = val % 2 != 0;
            val /= 2;
            let ip2 = val % 2 != 0;
            val /= 2;
            let ip3 = val % 2 != 0;
            val /= 2;
            let ip4 = val % 2 != 0;

            let op1 = evaluate(&circuit1, &[&[ip1, ip2], &[ip3, ip4]]);
            let op2 = evaluate(&circuit2, &[&[ip1, ip2], &[ip3, ip4]]);

            assert_eq!(op1, op2);
        }
    }

    #[test]
    fn test_get_circuit_3() {
        let circuit1 = BinaryCircuit::parse(AES128_CIRCUIT).unwrap();

        let obtained = get_bristol_fashion(&circuit1);

        let circuit2 = BinaryCircuit::parse(&obtained).unwrap();

        let mut rng = StdRng::from_entropy();
        for _ in 0..20 {
            let mut key = [0u8; 16];
            let mut msg = [0u8; 16];

            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut msg);

            let keybool =
                binstr_to_boolvec(&u8_vec_to_binary_string(key.to_vec()));
            let msgbool =
                binstr_to_boolvec(&u8_vec_to_binary_string(msg.to_vec()));

            let op1 = evaluate(&circuit1, &[&keybool, &msgbool]);
            let op2 = evaluate(&circuit2, &[&keybool, &msgbool]);

            assert_eq!(op1, op2);
        }
    }

    #[test]
    fn test_get_circuit_4() {
        let circuit1 = build_sha256_circuit(256);

        let obtained = get_bristol_fashion(&circuit1);

        let circuit2 = BinaryCircuit::parse(&obtained).unwrap();

        let mut rng = StdRng::from_entropy();
        for _ in 0..20 {
            let mut key = [0u8; 32];

            rng.fill_bytes(&mut key);

            let keybool =
                binstr_to_boolvec(&u8_vec_to_binary_string(key.to_vec()));

            let op1 = evaluate(&circuit1, &[&keybool]);
            let op2 = evaluate(&circuit2, &[&keybool]);

            assert_eq!(op1, op2);
        }
    }

    #[test]
    fn test_get_circuit_5() {
        let pub_seed = u8_vec_to_binary_string(vec![0u8; 32]);
        let address = u8_vec_to_binary_string(vec![0u8; 20]);

        let circuit1 = build_expand_seed_circuit(&address, &pub_seed);
        let obtained = get_bristol_fashion(&circuit1);
        let circuit2 = BinaryCircuit::parse(&obtained).unwrap();

        let mut rng = StdRng::from_entropy();
        for _ in 0..2 {
            let mut key = [0u8; 32];

            rng.fill_bytes(&mut key);

            let input_seed =
                binstr_to_boolvec(&u8_vec_to_binary_string(key.to_vec()));

            let op1 = evaluate(&circuit1, &[&input_seed]);
            let op2 = evaluate(&circuit2, &[&input_seed]);

            assert_eq!(op1, op2);
        }
    }

    #[test]
    fn test_get_circuit_6() {
        let seed_byte = vec![1; 32];

        let pub_seed = u8_vec_to_binary_string(seed_byte);
        let address = u8_vec_to_binary_string(vec![0; 5 * 4]);

        let circuit1 = build_pk_gen_circuit(&address, &pub_seed);
        let obtained = get_bristol_fashion(&circuit1);
        let circuit2 = BinaryCircuit::parse(&obtained).unwrap();

        let mut rng = StdRng::from_entropy();
        for _ in 0..1 {
            let mut key = [0u8; 32];

            rng.fill_bytes(&mut key);

            let input_seed =
                binstr_to_boolvec(&u8_vec_to_binary_string(key.to_vec()));

            let op1 = evaluate(&circuit1, &[&input_seed]);
            let op2 = evaluate(&circuit2, &[&input_seed]);

            assert_eq!(op1, op2);
        }
    }

    #[test]
    fn test_get_circuit_7() {
        let seed_byte = vec![1; 32];

        let pub_seed = u8_vec_to_binary_string(seed_byte);
        let address = u8_vec_to_binary_string(vec![0; 5 * 4]);

        let msg = [
            72, 236, 137, 90, 32, 66, 13, 191, 81, 59, 6, 233, 46, 155, 224,
            164, 153, 48, 233, 152, 231, 111, 120, 222, 117, 212, 246, 88,
            235, 159, 27, 4,
        ];

        let circuit1 = build_sign_circuit(&msg, &address, &pub_seed);
        let obtained = get_bristol_fashion(&circuit1);
        let circuit2 = BinaryCircuit::parse(&obtained).unwrap();

        let mut rng = StdRng::from_entropy();
        for _ in 0..1 {
            let mut key = [0u8; 32];

            rng.fill_bytes(&mut key);

            let input_seed =
                binstr_to_boolvec(&u8_vec_to_binary_string(key.to_vec()));

            let op1 = evaluate(&circuit1, &[&input_seed]);
            let op2 = evaluate(&circuit2, &[&input_seed]);

            assert_eq!(op1, op2);
        }
    }
}
