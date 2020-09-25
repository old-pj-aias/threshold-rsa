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

    let pubkey1 = RSAPublicKey::new(BigUint::from(3841 as u32), BigUint::from(17 as u32)).unwrap();
    pubkeys.add(pubkey1.clone());

    let pubkey2 = RSAPublicKey::new(BigUint::from(4897 as u32), BigUint::from(11 as u32)).unwrap();
    pubkeys.add(pubkey2.clone());

    let pubkey3 = RSAPublicKey::new(BigUint::from(5029 as u32), BigUint::from(13 as u32)).unwrap();
    pubkeys.add(pubkey3);

    let msg = BigUint::from(452009 as u64).to_bytes_le();
    println!("{:?}", msg);

    let mut enc = super::Encryptor::new(2, pubkeys);
    enc.msg = Some(msg.clone());

    let cipher = enc.encrypt();
    println!("{:?}", cipher.cipher);

    let c = BigUint::from_bytes_le(&cipher.cipher);

    // todo: fix
    let expect = BigUint::from(79682507303 as u64);
    assert_eq!(c, expect);

    let privatekey = RSAPrivateKey::from_components(
        BigUint::from(3841 as u32),
        BigUint::from(17 as u32),
        BigUint::from(1289 as u32),
        vec![BigUint::from(23 as u32), BigUint::from(167 as u32)],
    );

    let privatekey = super::ThresholdPrivateKey::new(privatekey);
    let m1 = privatekey.calc_share(&cipher, &pubkey1);
    let uint_m1 = BigUint::from_bytes_le(&m1.share);

    let privatekey = RSAPrivateKey::from_components(
        BigUint::from(4897 as u32),
        BigUint::from(11 as u32),
        BigUint::from(3459 as u32),
        vec![BigUint::from(59 as u32), BigUint::from(83 as u32)],
    );

    let privatekey = super::ThresholdPrivateKey::new(privatekey);
    let m2 = privatekey.calc_share(&cipher, &pubkey2);
    let uint_m2 = BigUint::from_bytes_le(&m2.share);

    println!("m1={}", uint_m1);
    println!("m2={}", uint_m2);

    let shareset = super::ShareSet::new(vec![m1, m2]);
    let d = shareset.decrypt();
    let uint_d = BigUint::from_bytes_le(&d);

    println!("d={}", uint_d);

    assert_eq!(d, msg);
}
