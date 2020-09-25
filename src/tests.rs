use rand::rngs::OsRng;
use rsa::{BigUint, PublicKeyParts, RSAPrivateKey, RSAPublicKey};

#[test]
fn test_init_keys() {
    let mut rng = OsRng;
    let bits = 2048;

    let privkey = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pubkey = RSAPublicKey::from(&privkey);

    let mut pubkeys = super::ThresholdPublicKeySet::new();
    pubkeys.add(pubkey);

    super::ThresholdPrivateKey::new(privkey);
}

#[test]
fn test_prepare_msg() {
    let mut rng = OsRng;
    let bits = 2048;

    let privkey = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pubkey = RSAPublicKey::from(&privkey);

    let mut pubkeys = super::ThresholdPublicKeySet::new();
    pubkeys.add(pubkey);

    let privkey = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pubkey = RSAPublicKey::from(&privkey);
    pubkeys.add(pubkey);

    let privkey = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pubkey = RSAPublicKey::from(&privkey);
    pubkeys.add(pubkey);

    let mut enc = super::Encryptor::new(2, pubkeys);
    enc.prepare_message(b"abc");

    println!("{:?}", enc.msg);
}

#[test]
fn test_prepare_encrypt() {
    let mut rng = OsRng;
    let bits = 2048;

    let mut pubkeys = super::ThresholdPublicKeySet::new();

    let pubkey = RSAPublicKey::new(BigUint::from(3841 as u32), BigUint::from(17 as u32)).unwrap();
    pubkeys.add(pubkey);

    let pubkey = RSAPublicKey::new(BigUint::from(4897 as u32), BigUint::from(11 as u32)).unwrap();
    pubkeys.add(pubkey);

    let pubkey = RSAPublicKey::new(BigUint::from(5029 as u32), BigUint::from(13 as u32)).unwrap();
    pubkeys.add(pubkey);

    let msg = BigUint::from(452009 as u64).to_bytes_le();
    println!("{:?}", msg);

    let mut enc = super::Encryptor::new(2, pubkeys);
    enc.msg = Some(msg);

    let c = enc.encrypt();
    println!("{:?}", c.cipher);

    let c = BigUint::from_bytes_le(&c.cipher);

    // todo: fix
    let expect = BigUint::from(79682507303 as u64);
    assert_eq!(c, expect);
}
