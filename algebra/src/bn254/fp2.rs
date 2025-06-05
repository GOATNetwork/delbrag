use super::Fp;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fp2 {
    pub c0: Fp,
    pub c1: Fp,
}

impl Fp2 {
    pub fn new(c0: Fp, c1: Fp) -> Self {
        Fp2 { c0, c1 }
    }

    pub fn zero() -> Self {
        Fp2 { c0: Fp::zero(), c1: Fp::zero() }
    }

    pub fn one() -> Self {
        Fp2 { c0: Fp::one(), c1: Fp::zero() }
    }

    pub fn mul(&self, other: &Fp2) -> Fp2 {
        // (a + bu)*(c + du) = (ac - bd) + (ad + bc)u
        let a = &self.c0;
        let b = &self.c1;
        let c = &other.c0;
        let d = &other.c1;

        let ac = a * c;
        let bd = b * d;
        let ad = a * d;
        let bc = b * c;

        Fp2 { c0: &ac - &bd, c1: ad + bc }
    }

    pub fn conjugate(&self) -> Fp2 {
        Fp2 { c0: self.c0.clone(), c1: -&self.c1 }
    }

    pub fn norm(&self) -> Fp {
        // c0^2 + c1^2 (if u^2 = -1)
        let c0_sq = self.c0.clone() * self.c0.clone();
        let c1_sq = self.c1.clone() * self.c1.clone();
        c0_sq + c1_sq
    }

    pub fn inverse(&self) -> Option<Fp2> {
        // (a + bu)^(-1) = (a - bu) / (a^2 + b^2)
        let norm = self.norm();
        norm.inverse().map(|inv_norm| {
            let conj = self.conjugate();
            Fp2 { c0: conj.c0 * inv_norm.clone(), c1: conj.c1 * inv_norm }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn254::fp::MODULUS;

    #[test]
    fn test_fp2_zero_and_one() {
        let zero = Fp2::zero();
        let one = Fp2::one();
        assert_eq!(zero.c0, Fp::zero());
        assert_eq!(zero.c1, Fp::zero());
        assert_eq!(one.c0, Fp::one());
        assert_eq!(one.c1, Fp::zero());
    }

    #[test]
    fn test_fp2_mul() {
        let a = Fp2::new(Fp::new(3u32), Fp::new(4u32));
        let b = Fp2::new(Fp::new(1u32), Fp::new(2u32));
        let res = a.mul(&b);
        println!("res: {:?}, {}", res, MODULUS.to_string());
        // (3 + 4u)(1 + 2u) = (3*1 - 4*2) + (3*2 + 4*1)u = (-5 + 10u)

        let expected = Fp2::new(Fp::from(-5), Fp::new(10u32));

        assert_eq!(a.mul(&b), expected);
    }

    #[test]
    fn test_fp2_conjugate() {
        let a = Fp2::new(Fp::new(5u32), Fp::new(7u32));
        let conj = a.conjugate();
        assert_eq!(conj.c0, a.c0);
        assert_eq!(conj.c1, -a.c1.clone());
    }

    #[test]
    fn test_fp2_norm() {
        let a = Fp2::new(Fp::new(3u32), Fp::new(4u32));
        let norm = a.norm();
        let expected = Fp::new((3 * 3 + 4 * 4) % MODULUS.limbs[0]);
        assert_eq!(norm, expected);
    }

    #[test]
    fn test_fp2_inverse() {
        let a = Fp2::new(Fp::new(5u32), Fp::new(7u32));
        let inv = a.inverse().unwrap();
        let prod = a.mul(&inv);
        assert_eq!(prod.c0, Fp::one());
        assert_eq!(prod.c1, Fp::zero());
    }
}
