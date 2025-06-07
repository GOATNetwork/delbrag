use super::bitwise::{and, not, or, xor};
use crate::GateGenerator;

pub fn not_u32(x: u32, gp: &mut GateGenerator) -> u32 {
    let mut result = 0;
    for i in 0..32 {
        let bit = (x >> i) & 1 != 0;
        if not(bit, gp) {
            result |= 1 << i;
        }
    }
    result
}

// Bitwise ADD using only NAND-based gates
pub fn add_u32(a: u32, b: u32, gp: &mut GateGenerator) -> u32 {
    let mut result = 0;
    let mut carry = false;

    for i in 0..32 {
        let bit_a = (a >> i) & 1 != 0;
        let bit_b = (b >> i) & 1 != 0;

        let ab = xor(bit_a, bit_b, gp);
        let sum = xor(ab, carry, gp);
        let carry_out = or(and(ab, carry, gp), and(bit_a, bit_b, gp), gp);

        if sum {
            result |= 1 << i;
        }

        carry = carry_out;
    }

    result
}

// Subtraction via two's complement: a - b = a + (~b + 1)
pub fn sub_u32(a: u32, b: u32, gp: &mut GateGenerator) -> u32 {
    let b_neg = add_u32(not_u32(b, gp), 1, gp);
    add_u32(a, b_neg, gp)
}

// Multiplication using shift-and-add
pub fn mul_u32(mut a: u32, mut b: u32, gp: &mut GateGenerator) -> u32 {
    let mut result = 0;

    for _ in 0..32 {
        if b & 1 != 0 {
            result = add_u32(result, a, gp);
        }
        a <<= 1;
        b >>= 1;
    }

    result
}

// Exponentiation using binary exponentiation
pub fn exp_u32(mut base: u32, mut exp: u32, gp: &mut GateGenerator) -> u32 {
    let mut result = 1;
    while exp > 0 {
        if exp & 1 != 0 {
            result = mul_u32(result, base, gp);
        }
        base = mul_u32(base, base, gp);
        exp >>= 1;
    }
    result
}

#[cfg(test)]
pub mod tests {
    use super::*;
    #[test]
    fn test_u32_simple() {
        let a = 13;
        let b = 5;

        let mut gp = GateGenerator { gate_index: 0, gates: vec![] };

        let r_sub = sub_u32(a, b, &mut gp);
        let r_mul = mul_u32(a, b, &mut gp);
        let r_exp = exp_u32(a, b, &mut gp);
        assert_eq!(r_sub, a - b);
        assert_eq!(r_mul, a * b);
        assert_eq!(r_exp, a.pow(b));
    }
}
