use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Clone, Debug, PartialEq)]
pub enum GateType {
    Inp,
    Xor,
    Inv,
    And,
}

impl GateType {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "INP" => Some(GateType::Inp),
            "XOR" => Some(GateType::Xor),
            "INV" => Some(GateType::Inv),
            "AND" => Some(GateType::And),
            _ => None,
        }
    }
}

pub struct TopologicalGates {
    pub t_depth: usize,
    pub local_gates: Vec<Vec<BoolGate>>,
    pub interactive_gates: Vec<Vec<BoolGate>>,
}

impl TopologicalGates {
    fn new(depth: usize) -> Self {
        TopologicalGates {
            t_depth: depth,
            local_gates: vec![Vec::with_capacity(0); depth],
            interactive_gates: vec![Vec::with_capacity(0); depth],
        }
    }
}

#[derive(Clone)]
pub struct BoolGate {
    pub input: [usize; 2],
    pub output: usize,
    pub gate_type: GateType,
    pub depth: usize,
}

impl BoolGate {
    fn new(g_type: GateType, output: usize, depth: usize, input0: Option<usize>, input1: Option<usize>) -> Self {
        let mut inputs = [0; 2];

        if let Some(val) = input0 {
            inputs[0] = val;
        }

        if let Some(val) = input1 {
            inputs[1] = val;
        }
        BoolGate {
            input: inputs,
            output,
            gate_type: g_type,
            depth: depth,
        }
    }
    fn default() -> Self {
        BoolGate {
            input: [usize::default(); 2],
            output: usize::default(),
            gate_type: GateType::Xor, 
            depth: usize::default(),
        }
    }
}

pub trait Circuit {
    fn read_circuit_file(&mut self, file_name: &str);
    fn generate_topological_ordering(self) -> TopologicalGates;
}

#[derive(Clone)]
pub struct BooleanCircuit {
    pub gates: Vec<BoolGate>,
    pub wire_count: usize,
    pub input_wires: Vec<Vec<usize>>,
    pub output_wires: Vec<Vec<usize>>,
    pub num_and_gates: u64,
    pub depth: usize,
}

impl BooleanCircuit {
    pub fn new() -> Self {
        BooleanCircuit {
            gates: Vec::new(),
            wire_count: 0,
            input_wires: Vec::new(),
            output_wires: Vec::new(),
            num_and_gates: 0,
            depth: 0,
        }
    }
}

impl Circuit for BooleanCircuit {
    fn read_circuit_file(&mut self, file_name: &str) {
        let file = File::open(file_name).expect("Failed to open the circuit file");
        let mut reader = BufReader::new(file).lines();

        let mut num_gates: u64 = 0;
        let mut num_wires = 0;

        if let Some(Ok(line1)) = reader.next() {
            let mut parts = line1.split(" ");
            num_gates = parts.next().unwrap().parse().unwrap();
            num_wires = parts.next().unwrap().parse().unwrap();
        }

        self.gates.resize((num_wires + 1) as usize, BoolGate::default());

        self.wire_count = 0;
        let mut map_wire: Vec<usize> = vec![0; (num_wires + 1) as usize];

        if let Some(Ok(line1)) = reader.next() {
            let mut parts = line1.split(" ");
            if let Some(n_input_wires_str) = parts.next() {
                if let Ok(_num_inp_wires) = n_input_wires_str.parse::<u64>() {
                    for part in parts.clone() {
                        if let Ok(num) = part.parse::<usize>() {
                            let mut inp_wire: Vec<usize> = vec![0; num];
                            for j in 0..num {
                                self.wire_count += 1;
                                self.gates[self.wire_count] =
                                    BoolGate::new(GateType::Inp, self.wire_count, 0, None, None);
                                map_wire[self.wire_count] = self.wire_count;
                                inp_wire[j] = self.wire_count;
                            }
                            self.input_wires.push(inp_wire);
                        }
                    }
                } else {
                    println!("Failed to parse number of inputs");
                }
            }
        }

        let mut output_size: Vec<usize> = Vec::new();
        let mut num_output_wires: usize = 0;

        if let Some(Ok(line1)) = reader.next() {
            let mut parts = line1.split(" ");
            if let Some(n_output_usizes_str) = parts.next() {
                if let Ok(n_output_usizes) = n_output_usizes_str.parse::<usize>() {
                    output_size.resize(n_output_usizes, 0);
                    let mut count = 0;
                    for part in parts.clone() {
                        if let Ok(num) = part.parse::<usize>() {
                            output_size[count] = num;
                            num_output_wires += output_size[count];
                            count += 1;
                        }
                    }
                } else {
                    println!("Failed to parse number of outputs");
                }
            }
        }

        for _i in 0..num_gates {
            let mut num_input = 0;
            let mut num_output = 0;
            let mut input0: usize = 0;
            let mut input1: usize = 0;
            let mut output: usize = 0;
            let mut gate = String::new();

            if let Some(Ok(line1)) = reader.next() {
                let mut parts = line1.split(" ");
                if let Some(num_inputs_str) = parts.next() {
                    if let Ok(parsed_num_input) = num_inputs_str.parse::<usize>() {
                        num_input = parsed_num_input;
                        num_output = parts.next().unwrap().parse::<usize>().unwrap();
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

            output += 1;
            input0 += 1;
            if num_input > 1 {
                input1 += 1;
            }

            let mut depth = std::cmp::max(
                self.gates[map_wire[input0]].depth,
                self.gates[map_wire[input1]].depth,
            );

            let mut gt = GateType::Xor;

            if let Some(gtype) = GateType::from_str(&gate) {
                if gtype == GateType::And {
                    depth += 1;
                }
                gt = gtype;
            }
            
            if gt == GateType::And {
                self.num_and_gates += 1;
            }

            self.wire_count += 1;
            self.gates[self.wire_count] = BoolGate::new(
                gt.clone(),
                self.wire_count,
                depth,
                Some(map_wire[input0]),
                Some(map_wire[input1]),
            );
            map_wire[output] = self.wire_count;

            self.depth = std::cmp::max(self.depth, depth);
        }

        let mut wctr = num_wires - num_output_wires;
        for i in output_size {
            let mut temp: Vec<usize> = vec![0; i];
            for j in 0..i {
                wctr += 1;
                temp[j] = map_wire[wctr];
            }
            self.output_wires.push(temp);
        }
        assert!(self.wire_count == num_wires);
    }

    fn generate_topological_ordering(self) -> TopologicalGates {
        let mut tgates = TopologicalGates::new(self.depth + 1);
        for i in 1..self.gates.len() {
            let g = &self.gates[i];
            if g.gate_type == GateType::And {
                tgates.interactive_gates[g.depth].push(g.clone());
            } else if g.gate_type != GateType::Inp {
                tgates.local_gates[g.depth].push(g.clone());
            }
        }
        return tgates;
    }
}