use noxs::*;

const PASSWORD_HEX: &str = "b102a3049c060f";
const KEY_HEX: &str = "ba49c1d86ab3b281e3cafe626e84274d6600504ec8bb072149b356ce1faea48b";
const PLAINTEXT_HEX: &str = "6de01091d749f189c4e25aa315b314aa";
const NONCE_HEX: &str = "a71ea4bf40414e434bc54649";
const VERSION_HEX: &str = "01";
const SALT_HEX: &str = "01020304a71ea4bf40414e434bc54649";
const ENCRYPTED_HEX: &str = "91352cd42cf496937b700a902c01d9d4";
const TAG_HEX: &str = "adcacd100c31dc5b2fa4c1f4575e684f";
const CIPHERTEXT_HEX: &str = "0101020304a71ea4bf40414e434bc5464991352cd42cf496937b700a902c01d9d4adcacd100c31dc5b2fa4c1f4575e684f";

#[test]
fn test_key_derivation() {
    let password = hex::decode(PASSWORD_HEX).unwrap();
    let salt = hex::decode(SALT_HEX).unwrap();

    let key = derive_key(&password, &salt.try_into().unwrap());

    assert_eq!(hex::encode(key), KEY_HEX);
}

#[test]
fn test_encrypt1() {
    let key = hex::decode(KEY_HEX).unwrap();
    let salt = hex::decode(SALT_HEX).unwrap();
    let plaintext = hex::decode(PLAINTEXT_HEX).unwrap();

    let ciphertext: Vec<u8> = encrypt(&key.try_into().unwrap(), &salt.try_into().unwrap(), &plaintext).unwrap();
    assert_eq!(hex::encode(ciphertext), CIPHERTEXT_HEX);
}

#[test]
fn test_encrypt2() {
    let password = hex::decode(PASSWORD_HEX).unwrap();
    let plaintext = hex::decode(PLAINTEXT_HEX).unwrap();

    let ciphertext = encrypt_with_password(&password, &plaintext).unwrap();
    assert_eq!(ciphertext.len(), VERSION_PREFIX_LEN + ARGON2ID_SALT_LEN + plaintext.len() + CHACHAPOLY_TAG_LEN);
}

#[test]
fn test_decrypt() {
    let password = hex::decode(PASSWORD_HEX).unwrap();
    let key = hex::decode(KEY_HEX).unwrap();
    let ciphertext = hex::decode(CIPHERTEXT_HEX).unwrap();

    let plaintext = decrypt(&key.try_into().unwrap(), &ciphertext).unwrap();
    assert_eq!(hex::encode(plaintext),PLAINTEXT_HEX);
}
