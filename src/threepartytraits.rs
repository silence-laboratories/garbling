pub trait ThreePartyBinaryCircuit {
    fn garble_threeparty();
    fn parse_threeparty();
    fn push_evaluatorinput_threeparty();
    fn garbler_evaluate_threeparty();
    fn evaluate_plaintext_threeparty();
    fn evaluator_evaluate_threeparty();
}


pub trait  ThreePartyBinaryCircuitBuilder {
    fn get_next_evaluator_input_id_threeparty(&mut self) -> usize;
    fn evaluator_input_threeparty(&mut self) -> usize;
    fn evaluator_inputs_threeparty(&mut self, number_of_inputs: u16) -> Vec<usize>;    
}
