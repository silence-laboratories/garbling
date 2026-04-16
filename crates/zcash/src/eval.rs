use garbled_circuit::circuitop::{circuit::BinaryCircuit, gate::BinaryGate};

pub fn evaluate(circuit: &BinaryCircuit, inputs: &[&[bool]]) -> Vec<bool> {
    let mut w = vec![false; circuit.gates().len()];

    for gate in circuit.gates().iter() {
        let (out_gate, f_label) = match *gate {
            BinaryGate::Input { no, id, wire } => {
                let share = inputs[no as usize][id as usize];
                (wire, share)
            }

            BinaryGate::Constant { val, wire } => (wire, val),

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
