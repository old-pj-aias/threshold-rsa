use rand::rngs::OsRng;
use rand::Rng;

use rsa::{BigUint, PublicKeyParts, RSAPrivateKey, RSAPublicKey};

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

pub fn prepare_message(msg: &[u8], threshold: usize, pubkeyset: ThresholdPublicKeySet) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let mut l1 = BigUint::from(1 as u32);
    let mut l2 = BigUint::from(1 as u32);

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

    let msg = prepare_message(b"abc", 2, pubkeys);

    println!("{:?}", msg);
}
