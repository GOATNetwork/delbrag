use num_traits::{One, Zero};
use std::cmp::Ordering;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::ops::{Add, AddAssign, BitAnd, BitAndAssign, Mul, Rem, Shl, Shr};
use std::ops::{Div, Sub};

#[derive(Clone, PartialEq, Eq)]
pub struct BigUint {
    /// Least significant limb first (little endian)
    pub limbs: Vec<u32>,
}

impl Add for BigUint {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        let mut res = other;
        res.add_assign(&self);
        res
    }
}

impl Zero for BigUint {
    fn zero() -> Self {
        Self::from(0u32)
    }
    fn set_zero(&mut self) {
        self.limbs.clear();
    }

    fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }
}

impl Add<&BigUint> for &BigUint {
    type Output = BigUint;
    fn add(self, other: &BigUint) -> Self::Output {
        let mut res = self.clone();
        res.add_assign(other);
        res
    }
}

impl Add<&BigUint> for BigUint {
    type Output = BigUint;
    fn add(self, other: &BigUint) -> Self::Output {
        let mut res = self.clone();
        res.add_assign(other);
        res
    }
}

impl Mul<&BigUint> for &BigUint {
    type Output = BigUint;
    fn mul(self, rhs: &BigUint) -> Self::Output {
        // Handle zero cases
        if self.is_zero() || rhs.is_zero() {
            return BigUint::zero();
        }

        // Multiply digits using schoolbook multiplication
        let mut limbs = vec![0u32; self.limbs.len() + rhs.limbs.len()];
        for i in 0..self.limbs.len() {
            let mut carry = 0u64;
            for j in 0..rhs.limbs.len() {
                let prod = self.limbs[i] as u64 * rhs.limbs[j] as u64 + limbs[i + j] as u64 + carry;
                limbs[i + j] = prod as u32;
                carry = prod >> 32;
            }
            limbs[i + rhs.limbs.len()] = carry as u32;
        }

        // Remove leading zeros
        while limbs.len() > 1 && limbs.last() == Some(&0) {
            limbs.pop();
        }
        BigUint { limbs }
    }
}

impl One for BigUint {
    fn one() -> Self {
        Self::from(1u32)
    }
    fn set_one(&mut self) {
        self.limbs[0] = 1;
    }
    fn is_one(&self) -> bool {
        self.limbs.len() == 1 && { self.limbs[0] == 1 }
    }
}

use std::str::FromStr;

impl FromStr for BigUint {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err("empty string");
        }
        let mut result = BigUint::zero();
        let ten = BigUint::from(10u32);

        for c in s.chars() {
            if let Some(digit) = c.to_digit(10) {
                result = &result * &ten + &BigUint::from(digit);
            } else {
                return Err("invalid character");
            }
        }
        Ok(result)
    }
}
impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        let a = &self.limbs;
        let b = &other.limbs;
        a.len().cmp(&b.len()).then_with(|| a.iter().rev().cmp(b.iter().rev()))
    }
}

impl BigUint {
    /// Create a BigUint from a single u32 value
    pub fn new(limbs: Vec<u32>) -> Self {
        Self { limbs }
    }

    pub fn from_random_bits<R: rand::Rng + ?Sized>(rng: &mut R, bits: usize) -> Self {
        assert!(bits > 0);

        let n_words = bits.div_ceil(32);
        let mut limbs = (0..n_words).map(|_| rng.r#gen::<u32>()).collect::<Vec<_>>();

        // Mask unused bits in the top word
        let extra_bits = (32 * n_words) - bits;
        if extra_bits > 0 {
            let mask = u32::MAX >> extra_bits;
            limbs[n_words - 1] &= mask;
        }

        let mut out = BigUint { limbs };
        out.normalize();
        out
    }

    /// Serialize into a minimal little‐endian byte array.
    /// Always returns at least one byte (0 for the zero value).
    pub fn to_bytes_le(&self) -> Vec<u8> {
        // Pre-allocate enough space: 4 bytes per u32 word
        let mut out = Vec::with_capacity(self.limbs.len() * 4);

        // Dump each u32 word as 4 little‐endian bytes
        for &word in &self.limbs {
            out.extend_from_slice(&word.to_le_bytes());
        }

        // Trim any high-order zero bytes
        while out.len() > 1 && *out.last().unwrap() == 0 {
            out.pop();
        }

        out
    }

    fn to_u32_digits(&self) -> Vec<u32> {
        // Get little-endian bytes (LSB first)
        let mut bytes = self.to_bytes_le();
        // Pad so len % 4 == 0
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
        // Turn every 4 bytes into one u32 little-endian
        let mut words = bytes
            .chunks(4)
            .map(|chunk| {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(chunk);
                u32::from_le_bytes(arr)
            })
            .collect::<Vec<_>>();
        // Trim high zero words, but leave at least one
        while words.len() > 1 && *words.last().unwrap() == 0 {
            words.pop();
        }
        words
    }

    fn bits(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        // Convert to u32‐limbs (little‐endian)
        let limbs = self.to_u32_digits();
        let last = *limbs.last().unwrap();
        // Number of bits in the most‐significant limb:
        let top_bits = 32 - last.leading_zeros() as usize;
        // Plus 32 bits for each other limb
        top_bits + 32 * (limbs.len() - 1)
    }

    fn bit(&self, i: usize) -> bool {
        // Which limb and which bit within that limb?
        let limb_idx = i / 32;
        let bit_idx = i % 32;
        let limbs = self.to_u32_digits();
        if limb_idx >= limbs.len() {
            return false;
        }
        (limbs[limb_idx] & (1 << bit_idx)) != 0
    }

    pub fn modpow(&self, exp: &BigUint, modulus: &BigUint) -> BigUint {
        assert!(!modulus.is_zero(), "modulus must be non-zero");

        // Window size (in bits)
        const W: usize = 4;
        let window_mask: u32 = (1 << W) - 1;

        // Precompute base^1, base^3, ..., base^(2^W - 1)
        let mut precomp = Vec::with_capacity(1 << (W - 1));
        let base = self % modulus;
        precomp.push(base.clone()); // base^1

        // base^2
        let base2 = &(&base * &base) % modulus;
        // then base^(2*i+1) = base2^i * base
        for i in 1..(1 << (W - 1)) {
            let last = &precomp[i - 1];
            precomp.push(&(last * &base2) % modulus);
        }

        // Scan exponent from most‐significant bit down
        let mut result = BigUint::one();
        let bits = exp.bits();
        let mut i = bits;

        while i > 0 {
            // Take W bits (or fewer at the top)
            let chunk_len = if i >= W { W } else { i };
            let shift = i - chunk_len;
            let window = ((exp >> shift) & BigUint::from(window_mask)).to_u32_digits()[0] as usize;

            // Square result chunk_len times
            for _ in 0..chunk_len {
                result = &(&result * &result) % modulus;
            }

            // Multiply by precomp[(window-1)/2] if window is odd
            if window != 0 {
                // odd windows only stored: index = (window-1)/2
                let idx = (window - 1) >> 1;
                result = &(&result * &precomp[idx]) % modulus;
            }

            i = shift;
        }

        result
    }

    /// Add another BigUint to self
    pub fn add_assign(&mut self, other: &BigUint) {
        let mut carry = 0u64;
        let max_len = self.limbs.len().max(other.limbs.len());

        self.limbs.resize(max_len, 0);

        for i in 0..max_len {
            let a = self.limbs[i] as u64;
            let b = if i < other.limbs.len() { other.limbs[i] as u64 } else { 0 };

            let sum = a + b + carry;
            self.limbs[i] = sum as u32;
            carry = sum >> 32;
        }

        if carry != 0 {
            self.limbs.push(carry as u32);
        }
    }

    /// Multiply self by a u32
    pub fn mul_u32(&self, rhs: u32) -> BigUint {
        let mut result = Vec::with_capacity(self.limbs.len() + 1);
        let mut carry = 0u64;

        for &limb in &self.limbs {
            let prod = (limb as u64) * (rhs as u64) + carry;
            result.push(prod as u32);
            carry = prod >> 32;
        }

        if carry != 0 {
            result.push(carry as u32);
        }

        BigUint { limbs: result }
    }

    pub fn normalize(&mut self) {
        while !self.limbs.is_empty() && *self.limbs.last().unwrap() == 0 {
            self.limbs.pop();
        }
    }

    pub fn sub_assign(&mut self, other: &Self) {
        assert_ne!((*self).cmp(other), Ordering::Less);
        let mut borrow = 0u64;
        for i in 0..self.limbs.len() {
            let a = self.limbs[i] as u64;
            let b = *other.limbs.get(i).unwrap_or(&0) as u64;
            let val = a.wrapping_sub(b + borrow);
            self.limbs[i] = val as u32;
            borrow = if a < b + borrow { 1 } else { 0 };
        }
        self.normalize();
    }
    pub fn div_mod(&self, divisor: &BigUint) -> (BigUint, BigUint) {
        assert!(!divisor.is_zero(), "division by zero");

        if self.cmp(divisor) == Ordering::Less {
            return (BigUint::zero(), self.clone());
        }

        let mut quotient = vec![0u32; self.limbs.len()];
        let mut remainder = BigUint { limbs: vec![] };

        for i in (0..self.limbs.len()).rev() {
            // Shift remainder left by 32 bits and bring in self.limbs[i]
            remainder.limbs.insert(0, self.limbs[i]);
            remainder.normalize();

            // Estimate quotient digit
            let mut q = 0u32;
            if remainder.cmp(divisor) != Ordering::Less {
                // Binary search between 0..=u32::MAX
                let mut low = 0u32;
                let mut high = u32::MAX;
                while low <= high {
                    let mid = low.wrapping_add((high - low) / 2);
                    let prod = divisor.mul_u32(mid);
                    match prod.cmp(&remainder) {
                        Ordering::Greater => high = mid - 1,
                        _ => {
                            q = mid;
                            low = mid + 1;
                        }
                    }
                }

                remainder.sub_assign(&divisor.mul_u32(q));
            }
            quotient[i] = q;
        }

        let mut quotient = BigUint { limbs: quotient };
        quotient.normalize();
        remainder.normalize();

        (quotient, remainder)
    }
}

impl fmt::Debug for BigUint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &d in self.limbs.iter().rev() {
            write!(f, "{d}")?;
        }
        Ok(())
    }
}

/// >>> LEFT SHIFT
impl Shl<usize> for &BigUint {
    type Output = BigUint;

    fn shl(self, bits: usize) -> BigUint {
        let word_shift = bits / 32;
        let bit_shift = bits % 32;

        // start with word‐shifted zeros
        let mut result = vec![0; word_shift + self.limbs.len() + 1];

        // first, copy original words into shifted positions
        for (i, &w) in self.limbs.iter().enumerate() {
            let w_u64 = w as u64;
            result[i + word_shift] |= (w_u64 << bit_shift) as u32;
            // carry overflow bits into the next word
            result[i + word_shift + 1] |= (w_u64 >> (32 - bit_shift)) as u32;
        }

        let mut out = BigUint { limbs: result };
        out.normalize();
        out
    }
}

impl Shl<usize> for BigUint {
    type Output = BigUint;
    fn shl(self, bits: usize) -> BigUint {
        &self << bits
    }
}

/// >>> RIGHT SHIFT
impl Shr<usize> for &BigUint {
    type Output = BigUint;

    fn shr(self, bits: usize) -> BigUint {
        let word_shift = bits / 32;
        let bit_shift = bits % 32;

        // if shifting away all words, return zero
        if word_shift >= self.limbs.len() {
            return BigUint::zero();
        }

        // take the tail after dropping word_shift words
        let mut tail = self.limbs[word_shift..].to_vec();

        if bit_shift > 0 {
            let mut carry = 0u32;
            // shift each word right, pulling in carry from higher word
            for w in tail.iter_mut().rev() {
                let new_carry = *w << (32 - bit_shift);
                *w = (*w >> bit_shift) | carry;
                carry = new_carry;
            }
        }

        let mut out = BigUint { limbs: tail };
        out.normalize();
        out
    }
}

impl Shr<usize> for BigUint {
    type Output = BigUint;
    fn shr(self, bits: usize) -> BigUint {
        &self >> bits
    }
}

impl Rem for &BigUint {
    type Output = BigUint;
    fn rem(self, rhs: &BigUint) -> BigUint {
        self.div_mod(rhs).1
    }
}

// Sub (assuming self >= rhs)
impl Sub for BigUint {
    type Output = BigUint;
    fn sub(self, rhs: BigUint) -> BigUint {
        let mut copy = self.clone();
        copy.sub_assign(&rhs);
        copy
    }
}

impl Sub<&BigUint> for &BigUint {
    type Output = BigUint;
    fn sub(self, rhs: &BigUint) -> BigUint {
        let mut copy = self.clone();
        copy.sub_assign(rhs);
        copy
    }
}

impl AddAssign<&BigUint> for BigUint {
    fn add_assign(&mut self, rhs: &BigUint) {
        self.add_assign(rhs);
    }
}

impl Mul<BigUint> for BigUint {
    type Output = BigUint;
    fn mul(self, rhs: BigUint) -> BigUint {
        &self * &rhs
    }
}

impl Div for &BigUint {
    type Output = BigUint;

    fn div(self, rhs: &BigUint) -> BigUint {
        self.div_mod(rhs).0
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for BigUint {
    /// Convert to decimal string (slow but educational)
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.limbs.is_empty() {
            return write!(f, "0");
        }

        let mut value = self.clone();
        let ten = BigUint::from(10u32);
        let mut digits = vec![];
        while value > BigUint::zero() {
            let (q, r) = value.div_mod(&ten);
            let digit = r.limbs.first().copied().unwrap_or(0);
            digits.push(digit.to_string());
            value = q;
        }
        for ch in digits.iter().rev() {
            write!(f, "{ch}")?;
        }
        Ok(())
    }
}

impl From<u32> for BigUint {
    fn from(n: u32) -> Self {
        if n == 0 { BigUint { limbs: vec![] } } else { BigUint { limbs: vec![n] } }
    }
}

impl From<u64> for BigUint {
    fn from(n: u64) -> Self {
        let mut limbs = vec![];
        let mut n = n;
        while n > 0 {
            limbs.push((n & 0xFFFF_FFFF) as u32);
            n >>= 32;
        }
        if limbs.is_empty() {
            limbs.push(0);
        }
        BigUint { limbs }
    }
}

/// >>> BITWISE AND
impl<'b> BitAnd<&'b BigUint> for &BigUint {
    type Output = BigUint;

    fn bitand(self, rhs: &'b BigUint) -> BigUint {
        let n = self.limbs.len().min(rhs.limbs.len());
        let mut limbs = Vec::with_capacity(n);
        for i in 0..n {
            limbs.push(self.limbs[i] & rhs.limbs[i]);
        }
        let mut out = BigUint { limbs };
        out.normalize();
        out
    }
}

impl BitAnd for BigUint {
    type Output = BigUint;
    fn bitand(self, rhs: BigUint) -> BigUint {
        &self & &rhs
    }
}

impl BitAnd<BigUint> for &BigUint {
    type Output = BigUint;
    fn bitand(self, rhs: BigUint) -> BigUint {
        self & &rhs
    }
}

impl<'a> BitAnd<&'a BigUint> for BigUint {
    type Output = BigUint;
    fn bitand(self, rhs: &'a BigUint) -> BigUint {
        &self & rhs
    }
}

impl BitAndAssign for BigUint {
    fn bitand_assign(&mut self, rhs: BigUint) {
        let n = self.limbs.len().min(rhs.limbs.len());
        for i in 0..n {
            self.limbs[i] &= rhs.limbs[i];
        }
        self.limbs.truncate(n);
        self.normalize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_biguint_add_mul() {
        let mut a = BigUint::from(123456789u32);
        let b = BigUint::from(987654321u32);
        a += &b;
        assert_eq!(a.to_string(), "1111111110");

        let c = a.mul_u32(100000000);
        let d = &a * &BigUint::from(100000000u32);

        assert_eq!(c.to_string(), "111111111000000000");
        assert_eq!(c, d);
    }

    #[test]
    fn test_div_mod() {
        let mut rng = rand::thread_rng();
        for _ in 1..1000 {
            let ddi: usize = rng.gen_range(1..1000);
            let di: usize = rng.gen_range(1..1000);
            let dividend = BigUint::from_random_bits(&mut rng, ddi);
            let divisor = BigUint::from_random_bits(&mut rng, di);
            if divisor.is_zero() {
                continue;
            }
            let (q, r) = dividend.div_mod(&divisor);
            println!("{:?} * {:?} + {:?} - {:?}", q, divisor, r, dividend);
            let result = q * divisor + r - dividend;
            assert!(result.is_zero());
        }
    }

    #[test]
    fn bits_zero() {
        let z = BigUint::zero();
        assert_eq!(z.bits(), 0);
        // All bit positions should be false
        for i in 0..5 {
            assert!(!z.bit(i), "zero.bit({}) should be false", i);
        }
    }

    #[test]
    fn bits_small_values() {
        let one = BigUint::from(1u32);
        assert_eq!(one.bits(), 1);
        assert!(one.bit(0));
        assert!(!one.bit(1));

        let two = BigUint::from(2u32); // 10₂
        assert_eq!(two.bits(), 2);
        assert!(!two.bit(0));
        assert!(two.bit(1));
        assert!(!two.bit(2));

        let five = BigUint::from(5u32); // 101₂
        assert_eq!(five.bits(), 3);
        assert!(five.bit(0));
        assert!(!five.bit(1));
        assert!(five.bit(2));
        assert!(!five.bit(3));
    }

    #[test]
    fn bits_multi_limb() {
        // Construct a number spanning >32 bits:
        // e.g. 1 << 40  + 1 << 5  => bits() = 41
        let high = BigUint::one() << 40;
        let low5 = BigUint::one() << 5;
        let n = high.clone() + low5.clone();
        assert_eq!(n.bits(), 41);

        // Check the set bits:
        assert!(n.bit(40), "bit 40 should be set");
        assert!(n.bit(5), "bit 5 should be set");

        // Check some unset bits around:
        for &i in &[0, 1, 4, 6, 39, 41, 50] {
            assert!(!n.bit(i), "bit {} should be unset", i);
        }
    }

    #[test]
    fn bits_consecutive_ones() {
        // Number = 0b11111 (31 decimal), bits() should be 5
        let m = BigUint::from(31u32);
        assert_eq!(m.bits(), 5);
        for i in 0..5 {
            assert!(m.bit(i), "bit {} should be 1", i);
        }
        assert!(!m.bit(5));
    }

    #[test]
    fn shl_small_bits() {
        let x = BigUint::from(1u32);
        // 1 << 0 == 1
        assert_eq!((&x << 0).to_u64(), 1);
        // 1 << 5 == 32
        assert_eq!((&x << 5).to_u64(), 32);
        // 3 << 4 == 48
        let y = BigUint::from(3u32);
        assert_eq!((&y << 4).to_u64(), 48);
    }

    #[test]
    fn shl_word_aligned() {
        // shift by exactly 32 bits: should append a zero word
        let x = BigUint::from(0xDEADBEEFu32);
        let shifted = &x << 32;
        // expect digits = [0, 0xDEADBEEF]
        assert_eq!(shifted.limbs, vec![0, 0xDEADBEEF]);
    }

    #[test]
    fn shl_multi_word() {
        // form a two-word number: high<<32 | low
        let low = 0x89ABCDEFu64;
        let high = 0x01234567u64;
        let mut x = BigUint::from(low);
        x.limbs.push(high as u32);
        // x = high*2^32 + low
        // shift left by 4: every word shifts, carry across boundary
        let s = &x << 4;
        // manually compute: original number << 4
        let n = ((high << 32) | low) << 4;
        assert_eq!(s.to_u64(), n);
    }

    #[test]
    fn shr_small_bits() {
        let x = BigUint::from(32u32);
        // 32 >> 0 == 32
        assert_eq!((&x >> 0).to_u64(), 32);
        // 32 >> 5 == 1
        assert_eq!((&x >> 5).to_u64(), 1);
        // 48 >> 4 == 3
        let y = BigUint::from(48u32);
        assert_eq!((&y >> 4).to_u64(), 3);
    }

    #[test]
    fn shr_word_aligned() {
        // shift down by exactly 32 bits: dropping low word
        let mut x = BigUint::from(0x12345678u32);
        x.limbs.push(0x9ABCDEF0);
        // original = high*2^32 + low
        let shifted = &x >> 32;
        // expect only the high word remains
        assert_eq!(shifted.to_u64(), 0x9ABCDEF0);
    }

    #[test]
    fn shr_too_far() {
        // any shift >= bit‐length yields zero
        let x = BigUint::from(12345u32);
        let zero = &x >> 64;
        assert!(zero.is_zero());
    }

    // Helper to extract a Rust-native u64 when the value fits
    impl BigUint {
        fn to_u64(&self) -> u64 {
            let mut acc = 0u64;
            for (i, &w) in self.limbs.iter().enumerate().take(2) {
                acc |= (w as u64) << (32 * i);
            }
            acc
        }
    }

    #[test]
    fn bitand_basic() {
        // 0b1010 (10) & 0b1100 (12) = 0b1000 (8)
        let a = BigUint::from(0b1010_u64);
        let b = BigUint::from(0b1100_u64);
        let c = &a & &b;
        assert_eq!(c.to_u64(), 0b1000);
    }

    #[test]
    fn bitand_owned_and_ref() {
        // Ensure owned & ref and ref & owned both work
        let a = BigUint::from(0xFFFF_FFFFu64);
        let b = BigUint::from(0xFF00_FF00u64);
        let c1 = a.clone() & b.clone();
        let c2 = &a & b.clone();
        let c3 = a.clone() & &b;
        assert_eq!(c1.to_u64(), 0xFF00_FF00);
        assert_eq!(c2.to_u64(), 0xFF00_FF00);
        assert_eq!(c3.to_u64(), 0xFF00_FF00);

        // in-place
        let mut d = a.clone();
        d &= b;
        assert_eq!(d.to_u64(), 0xFF00_FF00);
    }

    #[test]
    fn bitand_different_lengths() {
        // a has two limbs (64-bit), b has one limb
        let low = 0xDEAD_BEEFu64;
        let high = 0x1234_5678u64;
        let mut a = BigUint::from(low);
        a.limbs.push(high as u32);
        let b = BigUint::from(0xFFFF_0000u64);
        // Only the low limb overlaps; high limb should be dropped after AND
        let c = &a & &b;
        assert_eq!(c.limbs.len(), 1);
        assert_eq!(c.to_u64(), (low & 0xFFFF_0000));
    }

    #[test]
    fn bitand_with_zero() {
        let a = BigUint::from(0x1234_5678u64);
        let zero = BigUint::zero();
        let c = &a & &zero;
        assert!(c.is_zero());
    }

    #[test]
    fn test_parse_from_str() {
        let str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
        let a = BigUint::from_str(str).unwrap();
        println!("{}", a.to_string());
        assert_eq!(str, a.to_string().as_str());

        let a = BigUint::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        )
        .unwrap();
        println!("{:?}", a.limbs);
        let modulus = BigUint {
            limbs: vec![
                4026531841, 1138881939, 2042196113, 674490440, 2172737629, 3092268470, 3778125865,
                811880050,
            ],
        };
        println!("{:?}", modulus);
        assert_eq!(a, modulus)
    }
}
