#![allow(dead_code)]
extern crate core;

use wrk17::Gate;

mod bigint;
mod biguint;
mod bitwise;
mod bn254;
mod u32;

pub use bigint::BigInt;
pub use biguint::BigUint;

pub struct GatePropogator {
    gate_index: u64,
    gates: Vec<Gate>,
}
