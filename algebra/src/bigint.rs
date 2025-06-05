use crate::BigUint;
use num_traits::Zero;
use std::cmp::Ordering;
use std::ops::Add;
use std::ops::Mul;
use std::ops::Neg;
use std::ops::Sub;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigInt {
    pub sign: bool, // false = positive, true = negative
    pub magnitude: BigUint,
}

impl BigInt {
    pub fn zero() -> Self {
        Self { sign: false, magnitude: BigUint::zero() }
    }

    pub fn from_biguint(sign: bool, magnitude: BigUint) -> Self {
        if magnitude.is_zero() { Self::zero() } else { Self { sign, magnitude } }
    }

    pub fn from_u32(n: u32) -> Self {
        Self::from_biguint(false, BigUint::from(n))
    }
}

impl Neg for BigInt {
    type Output = BigInt;

    fn neg(self) -> BigInt {
        if self.magnitude.is_zero() {
            self
        } else {
            BigInt { sign: !self.sign, magnitude: self.magnitude }
        }
    }
}

impl Neg for &BigInt {
    type Output = BigInt;

    fn neg(self) -> BigInt {
        if self.magnitude.is_zero() {
            BigInt::zero()
        } else {
            BigInt { sign: !self.sign, magnitude: self.magnitude.clone() }
        }
    }
}

impl Add for BigInt {
    type Output = BigInt;

    fn add(self, other: BigInt) -> BigInt {
        &self + &other
    }
}

impl Add<&BigInt> for &BigInt {
    type Output = BigInt;
    fn add(self, other: &BigInt) -> BigInt {
        match (self.sign, other.sign) {
            (false, false) => BigInt::from_biguint(false, &self.magnitude + &other.magnitude),
            (true, true) => BigInt::from_biguint(true, &self.magnitude + &other.magnitude),
            (false, true) => match self.magnitude.cmp(&other.magnitude) {
                Ordering::Greater => {
                    BigInt::from_biguint(false, &self.magnitude - &other.magnitude)
                }
                Ordering::Less => BigInt::from_biguint(true, &other.magnitude - &self.magnitude),
                Ordering::Equal => BigInt::zero(),
            },
            (true, false) => other + self,
        }
    }
}

impl Sub for BigInt {
    type Output = BigInt;
    fn sub(self, other: BigInt) -> BigInt {
        self + (-other)
    }
}

impl Sub<&BigInt> for &BigInt {
    type Output = BigInt;
    fn sub(self, other: &BigInt) -> BigInt {
        self + &(-other)
    }
}

impl Sub<&BigInt> for BigInt {
    type Output = BigInt;
    fn sub(self, other: &BigInt) -> BigInt {
        self + (-other)
    }
}

impl Sub<BigInt> for &BigInt {
    type Output = BigInt;
    fn sub(self, other: BigInt) -> BigInt {
        self + &(-other)
    }
}

impl Mul<&BigInt> for &BigInt {
    type Output = BigInt;

    fn mul(self, other: &BigInt) -> BigInt {
        let sign = self.sign ^ other.sign;
        BigInt::from_biguint(sign, &self.magnitude * &other.magnitude)
    }
}

impl PartialOrd for BigInt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigInt {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.sign, other.sign) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => self.magnitude.cmp(&other.magnitude),
            (true, true) => other.magnitude.cmp(&self.magnitude),
        }
    }
}

impl From<i32> for BigInt {
    fn from(n: i32) -> Self {
        if n < 0 {
            BigInt::from_biguint(true, BigUint::from((-n) as u32))
        } else {
            BigInt::from_biguint(false, BigUint::from(n as u32))
        }
    }
}

pub fn modinv_euclid(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let mut t = BigInt::zero();
    let mut new_t = BigInt::from_u32(1);
    let mut r = BigInt::from_biguint(false, m.clone());
    let mut new_r = BigInt::from_biguint(false, a.clone());

    while !new_r.magnitude.is_zero() {
        let quotient = &r.magnitude / &new_r.magnitude;
        let quotient_bi = BigInt::from_biguint(false, quotient);

        let tmp_t = new_t.clone();
        let tmp_r = new_r.clone();
        t = std::mem::replace(&mut new_t, &t - &quotient_bi * &tmp_t);
        r = std::mem::replace(&mut new_r, &r - &quotient_bi * &tmp_r);
    }

    if r.magnitude != BigUint::from(1u32) {
        return None;
    }

    if t.sign {
        t = t + BigInt::from_biguint(false, m.clone());
    }

    Some(t.magnitude)
}
