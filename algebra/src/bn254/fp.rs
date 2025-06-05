use crate::{BigInt, BigUint};
use num_traits::{One, Zero};
use once_cell::sync::Lazy;
use std::ops::{Add, Mul, Neg, Sub};

/// The BN254 base field modulus:
pub static MODULUS: Lazy<BigUint> = Lazy::new(|| BigUint {
    limbs: vec![
        4026531841, 1138881939, 2042196113, 674490440, 2172737629, 3092268470, 3778125865,
        811880050,
    ],
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fp(pub BigUint);
impl Fp {
    pub fn new<T: Into<BigUint>>(value: T) -> Self {
        let value = &(value.into()) % &*MODULUS;
        Fp(value)
    }

    pub fn from<T: Into<BigInt>>(value: T) -> Self {
        let n: BigInt = value.into();
        let big_n = match n.sign {
            false => n.magnitude.clone(),
            true => &*MODULUS - &n.magnitude,
        };
        Fp(big_n)
    }

    pub fn zero() -> Self {
        Fp(Zero::zero())
    }

    pub fn one() -> Self {
        Fp(One::one())
    }

    /// Raise to a big-endian exponent
    pub fn pow_be(&self, exp: &[u8]) -> Fp {
        let base = self.0.clone();
        let mut res = BigUint::one();
        for byte in exp {
            // square res 8 times, then multiply if bit is set
            for bit in (0..8).rev() {
                res = &(res.clone() * res.clone()) % &*MODULUS;
                if (byte >> bit) & 1u8 == 1 {
                    res = &(res * base.clone()) % &*MODULUS;
                }
            }
        }
        Fp::new(res)
    }
    pub fn inverse(&self) -> Option<Self> {
        if self.0.is_zero() {
            return None;
        }

        crate::bigint::modinv_euclid(&self.0, &MODULUS).map(Fp)
    }
}

impl Add for Fp {
    type Output = Fp;
    fn add(self, rhs: Fp) -> Fp {
        Fp::new(self.0 + rhs.0)
    }
}

impl Sub for Fp {
    type Output = Fp;
    fn sub(self, rhs: Fp) -> Fp {
        let m = MODULUS.clone();
        Fp::new((self.0 + m) - rhs.0)
    }
}

impl Sub<&Fp> for &Fp {
    type Output = Fp;
    fn sub(self, rhs: &Fp) -> Fp {
        let m = MODULUS.clone();
        Fp::new(&(&self.0 + &m) - &rhs.0)
    }
}

impl Mul for Fp {
    type Output = Fp;
    fn mul(self, rhs: Fp) -> Fp {
        Fp::new(self.0 * rhs.0)
    }
}

impl Mul<&Fp> for &Fp {
    type Output = Fp;
    fn mul(self, rhs: &Fp) -> Fp {
        Fp::new(&self.0 * &rhs.0)
    }
}

impl Neg for Fp {
    type Output = Fp;
    fn neg(self) -> Fp {
        if self.0.is_zero() { self } else { Fp::new(MODULUS.clone() - self.0) }
    }
}

impl Neg for &Fp {
    type Output = Fp;
    fn neg(self) -> Fp {
        if self.0.is_zero() { Fp::zero() } else { Fp::new(&*MODULUS - &self.0) }
    }
}
