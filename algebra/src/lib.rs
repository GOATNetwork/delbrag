#![allow(dead_code)]
extern crate core;

use wrk17::Gate;

mod bigint;
mod biguint;
mod bitwise;
mod bn254;
mod koalabear;
mod u32;

pub use bigint::BigInt;
pub use biguint::BigUint;

pub struct GateGenerator {
    gate_index: u32,
    gates: Vec<Gate>,
}
