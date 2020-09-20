use rand::rngs::OsRng;
use rsa::{BigUint, PublicKeyParts, RSAPrivateKey, RSAPublicKey};

struct ThresholdPrivateKey {
    pub key: RSAPrivateKey,
}

struct ThresholdPublicKeySet {
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
