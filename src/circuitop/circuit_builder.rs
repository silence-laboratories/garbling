use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
};

use crate::{
    circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
    config::garbling2pc_errors::FileParsingError,
};

/// `CircuitBuilder` is a struct used to construct a `BinaryCircuit`.
/// It maintains internal state during the circuit construction process.
/// Once the circuit is built and returned, the builder can either be discarded
/// or reused to construct a new circuit on top of the existing one.
#[derive(Clone)]
pub struct CircuitBuilder<BinaryCircuit> {
    /// Tracks the next available gate ID in the circuit.
    pub next_ref_id: usize,

    /// Tracks the next available input ID for the garbler.
    pub next_garbler_input_id: usize,

    /// Tracks the next available input ID for the evaluator.
    pub next_evaluator_input_id: usize,

    /// A mapping of constant values to their corresponding gate IDs.
    /// This allows reuse of constant gates instead of creating duplicates.
    pub const_map: HashMap<u16, usize>,

    /// The binary circuit being constructed.
    /// This is incrementally updated as new gates and inputs are added.
    /// Once the construction is complete, the circuit can be extracted from the builder.
    pub circ: BinaryCircuit,
}

/// Implementation of the `CircuitBuilder` struct.
/// Provides methods to construct and output a `BinaryCircuit`.
impl CircuitBuilder<BinaryCircuit> {
    /// Creates a new, empty `CircuitBuilder` instance.
    /// Initializes all tracking counters to zero and sets up an empty circuit.
    pub fn new() -> Self {
        CircuitBuilder {
            next_ref_id: 0,
            next_garbler_input_id: 0,
            next_evaluator_input_id: 0,
            const_map: HashMap::new(),
            circ: BinaryCircuit::new(0),
        }
    }

    /// Returns the built `BinaryCircuit`.
    pub fn finish(self) -> BinaryCircuit {
        self.circ
    }

    /// Retrieves the next available input ID for the garbler and increments the counter.
    fn get_next_garbler_input_id(&mut self) -> usize {
        let current = self.next_garbler_input_id;
        self.next_garbler_input_id += 1;
        current
    }

    /// Retrieves the next available input ID for the evaluator and increments the counter.
    fn get_next_evaluator_input_id(&mut self) -> usize {
        let current = self.next_evaluator_input_id;
        self.next_evaluator_input_id += 1;
        current
    }

    /// Retrieves the next available ciphertext ID for non-free gates.
    /// This ID is used to reference ciphertexts in the circuit.
    fn get_next_ciphertext_id(&mut self) -> usize {
        let current = self.circ.get_num_nonfree_gates();
        self.circ.increment_nonfree_gates();
        current
    }

    /// Retrieves the next available reference ID for a gate and increments the counter.
    fn get_next_ref_id(&mut self) -> usize {
        let current = self.next_ref_id;
        self.next_ref_id += 1;
        current
    }

    /// Adds a binary gate to the circuit and returns its reference ID.
    pub fn gate(&mut self, gate: BinaryGate) -> usize {
        self.circ.push_gate(gate);
        self.get_next_ref_id()
    }

    /// Adds a new garbler input gate to the circuit.
    /// Returns the reference ID of the created input gate.
    pub fn garbler_input(&mut self) -> usize {
        let id = self.get_next_garbler_input_id();
        let r = self.gate(BinaryGate::GarblerInput { id });
        self.circ.push_garbler_input(id);
        r
    }

    /// Adds a new evaluator input gate to the circuit.
    /// Returns the reference ID of the created input gate.
    pub fn evaluator_input(&mut self) -> usize {
        let id = self.get_next_evaluator_input_id();
        let r = self.gate(BinaryGate::EvaluatorInput { id });
        self.circ.push_evaluator_input(id);
        r
    }

    /// Adds multiple garbler input gates to the circuit.
    /// Returns a vector of reference IDs corresponding to the created inputs.
    pub fn garbler_inputs(&mut self, number_of_inputs: u16) -> Vec<usize> {
        let mut output: Vec<usize> = Vec::new();
        for _i in 0..number_of_inputs {
            output.push(self.garbler_input());
        }
        output
    }

    /// Adds multiple evaluator input gates to the circuit.
    /// Returns a vector of reference IDs corresponding to the created inputs.
    pub fn evaluator_inputs(&mut self, number_of_inputs: u16) -> Vec<usize> {
        // 0..number_of_inputs.iter().map(|q| self.evaluator_input()).collect()
        let mut output: Vec<usize> = Vec::new();
        for _i in 0..number_of_inputs {
            output.push(self.evaluator_input());
        }
        output
    }

    /// Adds an XOR gate to the circuit.
    /// Returns the reference ID of the resulting gate.
    pub fn xor(&mut self, xid: usize, yid: usize) -> usize {
        let gate = BinaryGate::Xor {
            xid,
            yid,
            out: None,
        };
        self.gate(gate)
    }

    /// Adds a NOT gate (negation) to the circuit.
    /// Returns the reference ID of the resulting gate.
    pub fn negate(&mut self, xid: usize) -> usize {
        let gate = BinaryGate::Inv { xid, out: None };
        self.gate(gate)
    }

    /// Adds an AND gate to the circuit.
    /// Returns the reference ID of the resulting gate.
    pub fn and(&mut self, xid: usize, yid: usize) -> usize {
        let gate = BinaryGate::And {
            xid,
            yid,
            id: self.get_next_ciphertext_id(),
            out: None,
        };

        self.gate(gate)
    }

    /// Adds a constant gate to the circuit.
    /// If the constant already exists in the circuit, returns its reference ID.
    /// Otherwise, creates a new constant gate, stores it in `const_map`, and returns its reference ID.
    pub fn constant(&mut self, val: u16) -> usize {
        match self.const_map.get(&val) {
            Some(&r) => r,
            None => {
                let gate = BinaryGate::Constant { val };
                let r = self.gate(gate);
                self.const_map.insert(val, r);
                self.circ.push_constant_gate(r);
                r
            }
        }
    }

    /// Marks a gate as an output in the circuit.
    pub fn output(&mut self, id: usize) {
        self.circ.push_output_gate(id);
    }

    pub fn parse(
        &mut self,
        file_name: &str,
        garbler_input_ids: &[usize],
        evaluator_input_ids: &[usize],
    ) -> Result<Vec<usize>, FileParsingError> {
        let file = File::open(file_name)?;
        let mut reader = BufReader::new(file).lines();

        let mut num_gates: usize = 0;
        let mut num_wires: usize = 0;

        if let Some(Ok(line1)) = reader.next() {
            let mut parts = line1.split(' ');
            num_gates = parts.next().unwrap().parse()?;
            num_wires = parts.next().unwrap().parse()?;
        }

        let mut num_garbler_inputs = 0;
        let mut num_evaluator_inputs = 0;
        let mut num_outputs = 0;

        if let Some(Ok(line1)) = reader.next() {
            let mut parts = line1.split(' ');
            if let Some(n_input_wires_str) = parts.next() {
                if let Ok(_num_inp_wires) = n_input_wires_str.parse::<u64>() {
                    if _num_inp_wires == 2 {
                        if let Some(num_garbl_inputs) = parts.next() {
                            if let Ok(_num_garbl_inputs) = num_garbl_inputs.parse::<usize>() {
                                if let Some(num_eval_inputs) = parts.next() {
                                    if let Ok(_num_eval_inputs) = num_eval_inputs.parse::<usize>() {
                                        num_garbler_inputs = _num_garbl_inputs;
                                        num_evaluator_inputs = _num_eval_inputs;
                                    } else {
                                        return Err(FileParsingError::InputNoParsingError());
                                    }
                                } else {
                                    return Err(FileParsingError::InputNoParsingError());
                                }
                            } else {
                                return Err(FileParsingError::InputNoParsingError());
                            }
                        } else {
                            return Err(FileParsingError::InputNoParsingError());
                        }
                    } else {
                        return Err(FileParsingError::InputCountError());
                    }
                } else {
                    return Err(FileParsingError::InputNoParsingError());
                }
            }
        }

        assert_eq!(num_garbler_inputs, garbler_input_ids.len());
        assert_eq!(num_evaluator_inputs, evaluator_input_ids.len());

        if let Some(Ok(line1)) = reader.next() {
            let mut parts = line1.split(' ');
            if let Some(n_output_usizes_str) = parts.next() {
                if let Ok(n_output_usizes) = n_output_usizes_str.parse::<usize>() {
                    if n_output_usizes == 1 {
                        if let Some(n_outputs) = parts.next() {
                            if let Ok(n_output) = n_outputs.parse::<usize>() {
                                num_outputs = n_output;
                            }
                        }
                    } else {
                        return Err(FileParsingError::OutputCountError());
                    }
                } else {
                    return Err(FileParsingError::OutputNoParsingError());
                }
            }
        }

        let mut id: usize = 0;
        let latest_ref = self.next_ref_id - num_garbler_inputs - num_evaluator_inputs;

        /////// NEED TO HANDLE OUTPUT GATES PROPERLY.

        for i in 0..num_gates {
            let num_input: usize;
            let mut _num_output = 0;
            let mut input0: usize = 0;
            let mut input1: usize = 0;
            let mut output: usize = 0;
            let mut gate = String::new();

            if let Some(Ok(line1)) = reader.next() {
                let mut parts = line1.split(' ');
                if let Some(num_inputs_str) = parts.next() {
                    if let Ok(parsed_num_input) = num_inputs_str.parse::<usize>() {
                        num_input = parsed_num_input;
                        _num_output = parts.next().unwrap().parse::<usize>()?;
                        input0 = parts.next().unwrap().parse::<usize>()?;
                        if num_input == 2 {
                            input1 = parts.next().unwrap().parse::<usize>()?
                        }
                        output = parts.next().unwrap().parse::<usize>()?;
                        if let Some(gate_str) = parts.next() {
                            gate = gate_str.to_string();
                        }
                    }
                }
            }
            if gate == "AND" {
                self.circ.push_gate(BinaryGate::And {
                    xid: input0 + latest_ref,
                    yid: input1 + latest_ref,
                    id,
                    out: Some(output + latest_ref),
                });
                id += 1;
            } else if gate == "XOR" {
                self.circ.push_gate(BinaryGate::Xor {
                    xid: input0 + latest_ref,
                    yid: input1 + latest_ref,
                    out: Some(output + latest_ref),
                });
            } else if gate == "INV" {
                self.circ.push_gate(BinaryGate::Inv {
                    xid: input0 + latest_ref,
                    out: Some(output + latest_ref),
                });
            } else {
                return Err(FileParsingError::FileFormatError(i));
            }
        }

        let mut output_wire_ids = vec![];

        for i in 0..num_outputs {
            output_wire_ids.push(num_wires - num_outputs + latest_ref + i);
        }

        self.next_ref_id = num_wires + latest_ref;

        Ok(output_wire_ids)
    }
}

/// Implements the `Default` trait for `CircuitBuilder<BinaryCircuit>`.
impl Default for CircuitBuilder<BinaryCircuit> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use crate::{
        circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
        customcircuits::comparison::build_comparison_circuit,
        garbling2pc::plaintext_operations::BinaryPlaintext,
    };

    use super::CircuitBuilder;

    #[test]
    fn test_circuit_builder() {
        let circuit = build_comparison_circuit();

        let required_circuit = BinaryCircuit {
            gates: vec![
                BinaryGate::EvaluatorInput { id: 0 },
                BinaryGate::GarblerInput { id: 0 },
                BinaryGate::EvaluatorInput { id: 1 },
                BinaryGate::GarblerInput { id: 1 },
                BinaryGate::Xor {
                    xid: 0,
                    yid: 1,
                    out: None,
                },
                BinaryGate::Xor {
                    xid: 2,
                    yid: 3,
                    out: None,
                },
                BinaryGate::Constant { val: 1 },
                BinaryGate::And {
                    xid: 4,
                    yid: 5,
                    id: 0,
                    out: None,
                },
                BinaryGate::Xor {
                    xid: 4,
                    yid: 5,
                    out: None,
                },
                BinaryGate::Xor {
                    xid: 7,
                    yid: 8,
                    out: None,
                },
                BinaryGate::Xor {
                    xid: 9,
                    yid: 6,
                    out: None,
                },
            ],
            garbler_input_ids: [0, 1].to_vec(),
            evaluator_input_ids: vec![0, 1],
            output_gate_ids: vec![10],
            constant_gate_ids: vec![6],
            num_nonfree_gates: 1,
            num_wires: 0,
        };

        assert_eq!(required_circuit, circuit);
    }

    #[test]
    fn test_circuit_builder_parse() {
        let mut builder = CircuitBuilder::new();

        let inputs_garb = builder.garbler_inputs(4);
        let inputs_eval = builder.evaluator_inputs(4);

        let xor_garb1 = builder.xor(inputs_garb[0], inputs_garb[1]);
        let xor_garb2 = builder.xor(inputs_garb[2], inputs_garb[3]);
        let xor_eval1 = builder.xor(inputs_eval[0], inputs_eval[1]);
        let xor_eval2 = builder.xor(inputs_eval[2], inputs_eval[3]);

        let outputs = builder
            .parse(
                "circuits/binmult.txt",
                [xor_garb1, xor_garb2].as_slice(),
                [xor_eval1, xor_eval2].as_slice(),
            )
            .unwrap();

        let mut builder2 = builder.clone();

        for i in outputs.clone() {
            builder.output(i);
        }

        let circuit = builder.finish();

        let circ2 = BinaryCircuit::parse("circuits/binmult.txt").unwrap();

        let mut outfin = true;
        for garb in 0..16 {
            for eval in 0..16 {
                let mut newgarb = garb;
                let garb0 = (newgarb % 2) != 0;
                newgarb /= 2;
                let garb1 = (newgarb % 2) != 0;
                newgarb /= 2;
                let garb2 = (newgarb % 2) != 0;
                newgarb /= 2;
                let garb3 = (newgarb % 2) != 0;

                let mut neweval = eval;
                let eval0 = (neweval % 2) != 0;
                neweval /= 2;
                let eval1 = (neweval % 2) != 0;
                neweval /= 2;
                let eval2 = (neweval % 2) != 0;
                neweval /= 2;
                let eval3 = (neweval % 2) != 0;

                let actgarb0 = garb0 ^ garb1;
                let actgarb1 = garb2 ^ garb3;

                let acteval0 = eval0 ^ eval1;
                let acteval1 = eval2 ^ eval3;

                let mut pl = BinaryPlaintext::new();

                let outs = pl
                    .evaluate(
                        circuit.clone(),
                        &[garb0, garb1, garb2, garb3],
                        &[eval0, eval1, eval2, eval3],
                    )
                    .unwrap();

                let mut pl2 = BinaryPlaintext::new();

                let outs2 = pl2
                    .evaluate(circ2.clone(), &[actgarb0, actgarb1], &[acteval0, acteval1])
                    .unwrap();

                outfin &= outs == outs2;
            }
        }
        assert!(outfin);

        let gext0 = builder2.garbler_input();
        let gext1 = builder2.garbler_input();

        let actouts = builder2
            .parse("circuits/binmult.txt", [gext0, gext1].as_slice(), &outputs)
            .unwrap();

        for i in actouts.clone() {
            builder2.output(i);
        }

        let circuit = builder2.finish();

        let mut outfin = true;
        for garb in 0..16 {
            for eval in 0..16 {
                let mut newgarb = garb;
                let garb0 = (newgarb % 2) != 0;
                newgarb /= 2;
                let garb1 = (newgarb % 2) != 0;
                newgarb /= 2;
                let garb2 = (newgarb % 2) != 0;
                newgarb /= 2;
                let garb3 = (newgarb % 2) != 0;

                let mut neweval = eval;
                let eval0 = (neweval % 2) != 0;
                neweval /= 2;
                let eval1 = (neweval % 2) != 0;
                neweval /= 2;
                let eval2 = (neweval % 2) != 0;
                neweval /= 2;
                let eval3 = (neweval % 2) != 0;

                let actgarb0 = garb0 ^ garb1;
                let actgarb1 = garb2 ^ garb3;

                let acteval0 = eval0 ^ eval1;
                let acteval1 = eval2 ^ eval3;

                let mut pl = BinaryPlaintext::new();

                let outs = pl
                    .evaluate(
                        circuit.clone(),
                        &[garb0, garb1, garb2, garb3, true, false],
                        &[eval0, eval1, eval2, eval3],
                    )
                    .unwrap();

                let mut pl2 = BinaryPlaintext::new();
                let mut pl3 = BinaryPlaintext::new();

                let outs2 = pl2
                    .evaluate(circ2.clone(), &[actgarb0, actgarb1], &[acteval0, acteval1])
                    .unwrap();

                let outs3 = pl3.evaluate(circ2.clone(), &[true, false], &outs2).unwrap();

                outfin &= outs == outs3;
            }
        }
        assert!(outfin);
    }
}
