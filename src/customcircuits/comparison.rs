// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crate::circuitop::{
    circuit::BinaryCircuit, circuit_builder::CircuitBuilder,
};

pub fn build_comparison_circuit() -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let garb = builder.new_inputs(2);
    let eval = builder.new_inputs(2);

    let eval_input_1 = eval[0];
    let garb_input_1 = garb[0];
    let eval_input_2 = eval[1];
    let garb_input_2 = garb[1];

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
