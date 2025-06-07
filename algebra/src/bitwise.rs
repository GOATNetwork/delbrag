use crate::GateGenerator;
use wrk17::Gate;

pub fn nand(a: bool, b: bool, gp: &mut GateGenerator) -> bool {
    let index = gp.gate_index;
    gp.gates.push(Gate::And(index, index + 1));
    gp.gates.push(Gate::Not(index + 2));
    gp.gate_index = index + 3;
    !(a && b)
}
pub fn not(a: bool, gp: &mut GateGenerator) -> bool {
    let index = gp.gate_index;
    gp.gates.push(Gate::Not(index));
    gp.gate_index = index + 1;
    !a
}

pub fn and(a: bool, b: bool, gp: &mut GateGenerator) -> bool {
    let index = gp.gate_index;
    gp.gates.push(Gate::And(index, index + 1));
    gp.gate_index = index + 2;
    not(nand(a, b, gp), gp)
}

pub fn or(a: bool, b: bool, gp: &mut GateGenerator) -> bool {
    nand(!a, !b, gp)
}

pub fn xor(a: bool, b: bool, gp: &mut GateGenerator) -> bool {
    let index = gp.gate_index;
    gp.gates.push(Gate::Xor(index, index + 1));
    gp.gate_index = index + 2;
    a ^ b
}
