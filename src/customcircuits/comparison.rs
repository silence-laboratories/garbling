use crate::{
    circuitop::{circuit::BinaryCircuit, circuit_builder::CircuitBuilder},
    garbling3pc::threepartytraits::ThreePartyBinaryCircuitBuilder,
};

pub fn build_comparison_circuit() -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let eval_input_1 = builder.evaluator_input();
    let garb_input_1 = builder.garbler_input();
    let eval_input_2 = builder.evaluator_input();
    let garb_input_2 = builder.garbler_input();

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

pub fn build_comparison_circuit_threeparty() -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let eval_input_1 = builder.evaluator_input_threeparty();
    let garb_input_1 = builder.garbler_input();
    let eval_input_2 = builder.evaluator_input_threeparty();
    let garb_input_2 = builder.garbler_input();

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
