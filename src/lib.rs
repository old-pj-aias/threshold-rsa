use rand::rngs::OsRng;
use rand::Rng;

use num_bigint_dig::traits::ModInverse;
use num_bigint_dig::BigUint as NumBigUint;

use rsa::{BigUint, PublicKeyParts, RSAPrivateKey, RSAPublicKey};

use std::borrow::Cow;

static SECURITY_PARAM: u32 = 10;

pub fn generate_random_ubigint(size: usize) -> BigUint {
    let size = size / 32;
    let random_bytes: Vec<u32> = (0..size).map(|_| rand::random::<u32>()).collect();
    return BigUint::new(random_bytes);
}

pub struct ThresholdPrivateKey {
    pub key: RSAPrivateKey,
}

pub struct ThresholdPublicKeySet {
    pub keys: Vec<RSAPublicKey>,
}

impl ThresholdPublicKeySet {
    pub fn new() -> Self {
        let keys: Vec<RSAPublicKey> = Vec::new();

        Self { keys: keys }
    }

    pub fn add(&mut self, key: RSAPublicKey) {
        self.keys.push(key)
    }
}

impl ThresholdPrivateKey {
    pub fn new(key: RSAPrivateKey) -> Self {
        ThresholdPrivateKey { key: key }
    }
}


pub fn prepare_message(msg: &[u8], threshold: usize, pubkeyset: &ThresholdPublicKeySet) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let mut l1 = BigUint::from(1 as u32);
    // let mut l2 = BigUint::from(1 as u32);

    let n = pubkeyset.keys.len();
    let i = n - threshold + 2;

    // calc l1
    for index in i..n {
        l1 *= pubkeyset.keys[index].n();
    }

    let l1 = l1.bits() as u32;

    // calc l
    let l = rng.gen_range(3 * SECURITY_PARAM, 4 * SECURITY_PARAM);

    // calc log(l + K)
    let log_l1_plus_k: u32 = 32 - (l1 + SECURITY_PARAM).leading_zeros();
    println!("{}", l1 + SECURITY_PARAM);
    println!("{}", 32 - log_l1_plus_k);

    // calc random bits
    // todo!("We can't say that random field size is random_field_len.");
    let random_field_len = l - SECURITY_PARAM - log_l1_plus_k;
    let random_field = generate_random_ubigint(random_field_len as usize).to_bytes_be();

    // calc size field
    let mut size_field = vec![0; log_l1_plus_k as usize];
    let size_field_len = (log_l1_plus_k as usize) - 1;
    size_field[size_field_len] = msg.len() as u8;

    // return result
    [random_field, msg.to_vec(), size_field].concat()
}

fn encrypt(msg: &[u8], pubkeyset: &ThresholdPublicKeySet) -> BigUint {
    let msg = BigUint::from_bytes_le(msg);

    let n = pubkeyset.keys.len();

    // calc N
    let mut N = BigUint::from(1 as u64);
    for key in &pubkeyset.keys {
        N *= key.n();

    }

    let mut C = BigUint::from(1 as u32);

    // calc C
    for j in 1..pubkeyset.keys.len() + 1 {
        let pubkey = &pubkeyset.keys[j - 1];

        let c = msg.modpow(pubkey.e(), pubkey.n());

        // calc Zj
        let mut Zj = BigUint::from(1 as u32);

        println!("j={}", j);
        for (i, key) in pubkeyset.keys.iter().enumerate() {
            if i != j  - 1 {
                Zj *= key.n();
            }
        }

        // calc Nj, Zj, Yj
        let Nj = pubkey.n().to_bytes_le();
        let Nj = NumBigUint::from_bytes_le(&Nj);

        let Zj = Zj.to_bytes_le();
        let Zj = NumBigUint::from_bytes_le(&Zj);

        let Yj = Zj
            .clone()
            .mod_inverse(&Nj)
            .unwrap()
            .to_biguint()
            .unwrap();

        let Zj = Zj.to_bytes_le();
        let Zj = BigUint::from_bytes_le(&Zj);

        let Yj = Yj.to_bytes_le();
        let Yj = BigUint::from_bytes_le(&Yj);

        C += (c * Zj * Yj) % N.clone();
    }

    C
}

#[test]
fn test_init_keys() {
    let mut rng = OsRng;
    let bits = 2048;

    let privkey = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pubkey = RSAPublicKey::from(&privkey);

    let mut pubkeys = ThresholdPublicKeySet::new();
    pubkeys.add(pubkey);

    ThresholdPrivateKey::new(privkey);
}

#[test]
fn test_prepare_msg() {
    let mut rng = OsRng;
    let bits = 2048;

    let privkey = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pubkey = RSAPublicKey::from(&privkey);

    let mut pubkeys = ThresholdPublicKeySet::new();
    pubkeys.add(pubkey);

    let privkey = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pubkey = RSAPublicKey::from(&privkey);
    pubkeys.add(pubkey);

    let privkey = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pubkey = RSAPublicKey::from(&privkey);
    pubkeys.add(pubkey);

    let msg = prepare_message(b"abc", 2, &pubkeys);

    println!("{:?}", msg);
}

#[test]
fn test_prepare_encrypt() {
    let mut rng = OsRng;
    let bits = 2048;

    let mut pubkeys = ThresholdPublicKeySet::new();

    let pubkey = RSAPublicKey::new(BigUint::from(3841 as u32), BigUint::from(17 as u32)).unwrap();
    pubkeys.add(pubkey);

    let pubkey = RSAPublicKey::new(BigUint::from(4897 as u32), BigUint::from(11 as u32)).unwrap();
    pubkeys.add(pubkey);

    let pubkey = RSAPublicKey::new(BigUint::from(5029 as u32), BigUint::from(13 as u32)).unwrap();
    pubkeys.add(pubkey);

    let msg = BigUint::from(452009 as u64).to_bytes_le();
    println!("{:?}", msg);

    let e = encrypt(&msg, &pubkeys);
    println!("{:?}", e);
}
