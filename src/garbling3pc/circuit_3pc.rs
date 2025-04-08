use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use crate::{
    circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
    config::garbling2pc_errors::FileParsingError,
};

use super::threepartytraits::ThreePartyBinaryCircuit;

/// Implements the `ThreePartyBinaryCircuit` trait for `BinaryCircuit`.
impl ThreePartyBinaryCircuit for BinaryCircuit {
    /// Parses a circuit definition from a file in the Bristol Fashion format
    /// to the format required for the three-party garbled-circuit protocol.
    /// Supports the fact that the evaluator's input is now doubled, and the xor
    /// of every pair of these inputs form the original evaluator's input.
    ///
    /// The Bristol Fashion format is a standard plaintext representation of
    /// boolean circuits, commonly used in secure computation protocols.
    /// More details can be found at:  
    /// <https://nigelsmart.github.io/MPC-Circuits/>
    ///
    /// # Arguments
    /// * `file_name` - A string slice representing the path to the circuit file.
    ///
    /// # Returns
    /// * `Ok(Self)` if the file is successfully parsed into a `BinaryCircuit`.
    /// * `Err(FileParsingError)` if there is an issue reading or parsing the file.
    fn parse_threeparty(file_name: &str) -> Result<Self, FileParsingError> {
        let file = File::open(file_name)?;
        let mut reader = BufReader::new(file).lines();

        let mut num_gates: usize = 0;
        let mut num_wires: usize = 0;

        if let Some(Ok(line1)) = reader.next() {
            let mut parts = line1.split(' ');
            num_gates = parts.next().unwrap().parse().unwrap();
            num_wires = parts.next().unwrap().parse().unwrap();
        }

        let mut output_circuit = Self::new(num_gates);
        let mut num_garbler_inputs = 0;
        let mut num_evaluator_inputs = 0;
        let mut num_outputs = 0;

        if let Some(Ok(line1)) = reader.next() {
            let mut parts = line1.split(' ');
            if let Some(n_input_wires_str) = parts.next() {
                if let Ok(_num_inp_wires) = n_input_wires_str.parse::<u64>() {
                    if _num_inp_wires >= 2 {
                        for _ in 0.._num_inp_wires - 1 {
                            if let Some(num_garbl_inputs) = parts.next() {
                                if let Ok(_num_garbl_inputs) = num_garbl_inputs.parse::<usize>() {
                                    num_garbler_inputs = _num_garbl_inputs;
                                } else {
                                    return Err(FileParsingError::InputNoParsingError());
                                }
                            } else {
                                return Err(FileParsingError::InputNoParsingError());
                            }
                        }
                        if let Some(num_eval_inputs) = parts.next() {
                            if let Ok(_num_eval_inputs) = num_eval_inputs.parse::<usize>() {
                                num_evaluator_inputs = _num_eval_inputs;
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

        for i in 0..num_garbler_inputs {
            output_circuit.push_gate(BinaryGate::GarblerInput { id: i });
            output_circuit.push_garbler_input(i);
        }

        for i in 0..num_evaluator_inputs {
            output_circuit.push_gate(BinaryGate::EvaluatorInput { id: 2 * i });
            output_circuit.push_evaluator_input(2 * i);
            output_circuit.push_gate(BinaryGate::EvaluatorInput { id: 2 * i + 1 });
            output_circuit.push_evaluator_input(2 * i + 1);
            output_circuit.push_gate(BinaryGate::Xor {
                xid: num_garbler_inputs + 3 * i,
                yid: num_garbler_inputs + 3 * i + 1,
                out: Some(num_garbler_inputs + 3 * i + 2),
            });
        }

        num_wires += 2 * num_evaluator_inputs;

        for i in 0..num_outputs {
            output_circuit.push_output_gate(num_wires - num_outputs + i)
        }

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
                        _num_output = parts.next().unwrap().parse::<usize>().unwrap();
                        input0 = parts.next().unwrap().parse::<usize>().unwrap();
                        if num_input == 2 {
                            input1 = parts.next().unwrap().parse::<usize>().unwrap()
                        }
                        output = parts.next().unwrap().parse::<usize>().unwrap();
                        if let Some(gate_str) = parts.next() {
                            gate = gate_str.to_string();
                        }
                    }
                }
            }

            if input1 >= num_garbler_inputs {
                if input1 < num_garbler_inputs + num_evaluator_inputs {
                    input1 -= num_garbler_inputs;
                    input1 = num_garbler_inputs + 3 * input1 + 2;
                } else {
                    input1 += 2 * num_evaluator_inputs;
                }
            }

            if input0 >= num_garbler_inputs {
                if input0 < num_garbler_inputs + num_evaluator_inputs {
                    input0 -= num_garbler_inputs;
                    input0 = num_garbler_inputs + 3 * input0 + 2;
                } else {
                    input0 += 2 * num_evaluator_inputs;
                }
            }

            if output >= num_garbler_inputs {
                if output < num_garbler_inputs + num_evaluator_inputs {
                    output -= num_garbler_inputs;
                    output = num_garbler_inputs + 3 * output + 2;
                } else {
                    output += 2 * num_evaluator_inputs;
                }
            }

            if gate == "AND" {
                output_circuit.push_gate(BinaryGate::And {
                    xid: input0,
                    yid: input1,
                    id,
                    out: Some(output),
                });
                id += 1;
            } else if gate == "XOR" {
                output_circuit.push_gate(BinaryGate::Xor {
                    xid: input0,
                    yid: input1,
                    out: Some(output),
                });
            } else if gate == "INV" {
                output_circuit.push_gate(BinaryGate::Inv {
                    xid: input0,
                    out: Some(output),
                });
            } else {
                return Err(FileParsingError::FileFormatError(i));
            }
        }
        Ok(output_circuit)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        circuitop::{circuit::BinaryCircuit, gate::BinaryGate},
        garbling3pc::threepartytraits::ThreePartyBinaryCircuit,
    };

    #[test]
    fn test_circuit_3pc() {
        let circuit = BinaryCircuit::parse_threeparty("circuits/binmult.txt").unwrap();

        let required_circuit = BinaryCircuit {
            gates: vec![
                BinaryGate::GarblerInput { id: 0 },
                BinaryGate::GarblerInput { id: 1 },
                BinaryGate::EvaluatorInput { id: 0 },
                BinaryGate::EvaluatorInput { id: 1 },
                BinaryGate::Xor {
                    xid: 2,
                    yid: 3,
                    out: Some(4),
                },
                BinaryGate::EvaluatorInput { id: 2 },
                BinaryGate::EvaluatorInput { id: 3 },
                BinaryGate::Xor {
                    xid: 5,
                    yid: 6,
                    out: Some(7),
                },
                BinaryGate::And {
                    xid: 0,
                    yid: 4,
                    id: 0,
                    out: Some(8),
                },
                BinaryGate::And {
                    xid: 0,
                    yid: 7,
                    id: 1,
                    out: Some(9),
                },
                BinaryGate::And {
                    xid: 1,
                    yid: 4,
                    id: 2,
                    out: Some(10),
                },
                BinaryGate::And {
                    xid: 1,
                    yid: 7,
                    id: 3,
                    out: Some(11),
                },
                BinaryGate::Xor {
                    xid: 9,
                    yid: 10,
                    out: Some(12),
                },
                BinaryGate::Xor {
                    xid: 12,
                    yid: 11,
                    out: Some(13),
                },
            ],
            garbler_input_ids: vec![0, 1],
            evaluator_input_ids: vec![0, 1, 2, 3],
            output_gate_ids: vec![12, 13],
            constant_gate_ids: vec![],
            num_nonfree_gates: 0,
            num_wires: 0,
        };

        assert_eq!(required_circuit, circuit);
    }
}
