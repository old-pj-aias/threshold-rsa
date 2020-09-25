mod tests;
mod utils;

use rand::Rng;
use rsa::{BigUint, PublicKeyParts, RSAPrivateKey, RSAPublicKey};

static SECURITY_PARAM: u32 = 10;

pub struct Share {
    share: Vec<u8>,
    pubkey: RSAPublicKey,
}

pub struct ShareSet {
    shares: Vec<Share>,
}

impl ShareSet {
    pub fn new(shares: Vec<Share>) -> Self {
        Self { shares: shares }
    }

    pub fn decrypt(&self) -> Vec<u8> {
        let mut m = BigUint::from(0 as u64);

        let mut n = BigUint::from(1 as u64);
        for s in &self.shares {
            n *= s.pubkey.n()
        }

        for (i, si) in self.shares.iter().enumerate() {
            for (j, sj) in self.shares.iter().enumerate() {
                if i == j {
                    continue;
                };

                let c = BigUint::from_bytes_le(&si.share);
                let n1 = si.pubkey.n();
                let n2 = sj.pubkey.n();

                let i = utils::mod_inverse(n2, n1);

                m += c * n2 * i % n.clone();
            }
        }

        m = m % n;
        m.to_bytes_le()
    }
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
        Self { key: key }
    }

    pub fn calc_share(&self, cipher: &Cipher, pubkey: &RSAPublicKey) -> Share {
        let c = BigUint::from_bytes_le(&cipher.cipher);
        let p = c.modpow(self.key.d(), self.key.n());

        Share {
            share: p.to_bytes_le(),
            pubkey: pubkey.clone(),
        }
    }
}

pub struct Encryptor {
    pub msg: Option<Vec<u8>>,
    pub threshold: usize,
    pub pubkeyset: ThresholdPublicKeySet,
}

pub struct Cipher {
    pub cipher: Vec<u8>,
    pub threshold: usize,
}

pub struct Decryptor {
    pub cipher: Cipher,
    pub shares: ShareSet,
}

impl Encryptor {
    pub fn new(threshold: usize, pubkeyset: ThresholdPublicKeySet) -> Self {
        Self {
            msg: None,
            threshold: threshold,
            pubkeyset: pubkeyset,
        }
    }

    pub fn prepare_message(&mut self, msg: &[u8]) {
        let mut rng = rand::thread_rng();

        let mut l1 = BigUint::from(1 as u32);
        // let mut l2 = BigUint::from(1 as u32);

        let n = self.pubkeyset.keys.len();
        let i = n - self.threshold + 2;

        // calc l1
        for index in i..n {
            l1 *= self.pubkeyset.keys[index].n();
        }

        let l1 = l1.bits() as u32;

        // calc l
        let l = rng.gen_range(3 * SECURITY_PARAM, 4 * SECURITY_PARAM);

        // calc log(l + K)
        let log_l1_plus_k: u32 = 32 - (l1 + SECURITY_PARAM).leading_zeros();

        // calc random bits
        // todo!("We can't say that random field size is random_field_len.");
        let random_field_len = l - SECURITY_PARAM - log_l1_plus_k;
        let random_field = utils::generate_random_ubigint(random_field_len as usize).to_bytes_be();

        // calc size field
        let mut size_field = vec![0; log_l1_plus_k as usize];
        let size_field_len = (log_l1_plus_k as usize) - 1;
        size_field[size_field_len] = msg.len() as u8;

        // return result
        let msg = [random_field, msg.to_vec(), size_field].concat();
        self.msg = Some(msg.clone());
    }

    pub fn encrypt(&self) -> Cipher {
        let msg = self.msg.as_ref().expect("Not prepared");
        let msg = BigUint::from_bytes_le(&msg);

        let n = self.pubkeyset.keys.len();

        // calc N
        let mut N = BigUint::from(1 as u64);
        for key in &self.pubkeyset.keys {
            N *= key.n();
        }

        let mut C = BigUint::from(0 as u32);

        // calc C
        for j in 1..self.pubkeyset.keys.len() + 1 {
            let pubkey = &self.pubkeyset.keys[j - 1];

            let c = msg.modpow(pubkey.e(), pubkey.n());

            // calc Zj
            let mut Zj = BigUint::from(1 as u32);

            for (i, key) in self.pubkeyset.keys.iter().enumerate() {
                if i != j - 1 {
                    Zj *= key.n();
                }
            }

            // calc Nj, Zj, Yj
            let Nj = pubkey.n();
            let Yj = utils::mod_inverse(&Zj, &Nj);

            C += (c * Zj * Yj) % N.clone();
        }

        let C = C.to_bytes_le();

        Cipher {
            cipher: C,
            threshold: self.threshold,
        }
    }
}
