#[derive(Clone, Debug, PartialEq)]
pub enum BinaryGate {
    GarblerInput {
        id: usize,
    },
    EvaluatorInput {
        id: usize,
    },
    Constant {
        val: u16,
    },
    Xor {
        xid: usize,
        yid: usize,
        out: Option<usize>,
    },
    And {
        xid: usize,
        yid: usize,
        id: usize,
        out: Option<usize>,
    },
    Inv {
        xid: usize,
        out: Option<usize>,
    },
}
