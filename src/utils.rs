use rsa::BigUint;

use num_bigint_dig::traits::ModInverse;
use num_bigint_dig::BigUint as NumBigUint;

pub fn generate_random_ubigint(size: usize) -> BigUint {
    let size = size / 32;
    let random_bytes: Vec<u32> = (0..size).map(|_| rand::random::<u32>()).collect();
    return BigUint::new(random_bytes);
}

pub fn mod_inverse(g: &BigUint, n: &BigUint) -> BigUint {
    let g = g.to_bytes_le();
    let g = NumBigUint::from_bytes_le(&g);

    let n = n.to_bytes_le();
    let n = NumBigUint::from_bytes_le(&n);

    let i = g
        .clone()
        .mod_inverse(&n)
        .expect("failed to calc inverse")
        .to_biguint()
        .unwrap();

    let i = i.to_bytes_le();
    BigUint::from_bytes_le(&i)
}
