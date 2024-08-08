use noxs::*;

const PASSWORD_HEX: &str = "b102a3049c060f";
const KEY_HEX: &str = "ba49c1d86ab3b281e3cafe626e84274d6600504ec8bb072149b356ce1faea48b";
const PLAINTEXT_HEX: &str = "6de01091d749f189c4e25aa315b314aa";
const VERSION_HEX: &str = "01";
const SALT_HEX: &str = "01020304a71ea4bf40414e434bc54649";
const TAG_HEX: &str = "adcacd100c31dc5b2fa4c1f4575e684f";
const CIPHERTEXT_HEX: &str = "91352cd42cf496937b700a902c01d9d4adcacd100c31dc5b2fa4c1f4575e684f";
const CIPHERTEXT_COMBINED_HEX: &str = "0101020304a71ea4bf40414e434bc5464991352cd42cf496937b700a902c01d9d4adcacd100c31dc5b2fa4c1f4575e684f";

#[test]
fn kdf1() {
    let password = hex::decode(PASSWORD_HEX).unwrap();
    let salt = hex::decode(SALT_HEX).unwrap();
    let key = derive_key(&password, &salt.try_into().unwrap());
    assert_eq!(hex::encode(key), KEY_HEX);
}

#[test]
fn kdf2() {
    let password = vec![];
    let salt = vec![0; 16];
    let key = derive_key(&password, &salt.try_into().unwrap());
    assert_eq!(key.len(), 32);
}

#[test]
fn encrypt1() {
    let key = hex::decode(KEY_HEX).unwrap();
    let salt = hex::decode(SALT_HEX).unwrap();
    let plaintext = hex::decode(PLAINTEXT_HEX).unwrap();
    let ciphertext: Vec<u8> = encrypt(&key.try_into().unwrap(), &salt.try_into().unwrap(), &plaintext).unwrap();
    assert_eq!(hex::encode(ciphertext), CIPHERTEXT_HEX);
}

#[test]
fn encrypt3() {
    let password = vec![];
    let plaintext = vec![];
    let (_, ciphertext) = encrypt_with_password(&password, &plaintext).unwrap();
    assert_eq!(ciphertext.len(), CHACHAPOLY_TAG_LEN);
}

#[test]
fn decrypt1() {
    let key = hex::decode(KEY_HEX).unwrap();
    let data = hex::decode(CIPHERTEXT_COMBINED_HEX).unwrap();
    data.get(..VERSION.len()).filter(|&v| v == &VERSION[..]).unwrap();
    let salt = data.get(VERSION.len()..VERSION.len() + ARGON2ID_SALT_LEN).unwrap();
    let ciphertext = data.get(VERSION.len() + ARGON2ID_SALT_LEN..).filter(|slice| slice.len() >= CHACHAPOLY_TAG_LEN).unwrap();
    assert_eq!(hex::encode(ciphertext), CIPHERTEXT_HEX);
    let plaintext = decrypt(&key.try_into().unwrap(), salt[ARGON2ID_SALT_LEN - CHACHAPOLY_NONCE_LEN..].try_into().unwrap(), ciphertext).unwrap();
    assert_eq!(hex::encode(plaintext), PLAINTEXT_HEX);
}

#[test]
fn decrypt2() {
    let password = hex::decode(PASSWORD_HEX).unwrap();
    let salt = hex::decode(SALT_HEX).unwrap();
    let ciphertext = hex::decode(CIPHERTEXT_HEX).unwrap();
    let plaintext = decrypt_with_password(&password, &salt.try_into().unwrap(), &ciphertext).unwrap();
    assert_eq!(hex::encode(plaintext), PLAINTEXT_HEX);
}

#[test]
fn decrypt3() {
    let password = hex::decode(PASSWORD_HEX).unwrap();
    let data = hex::decode(format!("{}{}{}", VERSION_HEX, SALT_HEX, TAG_HEX)).unwrap();
    data.get(..VERSION.len()).filter(|&v| v == &VERSION[..]).unwrap();
    let salt = data.get(VERSION.len()..VERSION.len() + ARGON2ID_SALT_LEN).unwrap();
    let ciphertext = data.get(VERSION.len() + ARGON2ID_SALT_LEN..).filter(|slice| slice.len() >= CHACHAPOLY_TAG_LEN).unwrap();
    let result = decrypt_with_password(&password, &salt.try_into().unwrap(), &ciphertext);
    assert!(matches!(result, Err(CipherError::DecryptionFailed)));
}

#[test]
fn decrypt4() {
    let data = hex::decode(format!("ff{}{}", SALT_HEX, TAG_HEX)).unwrap();
    let version = data.get(..VERSION.len()).filter(|&v| v == &VERSION[..]);
    assert!(matches!(version, None));
    let salt = data.get(VERSION.len()..VERSION.len() + ARGON2ID_SALT_LEN).unwrap();
    assert_eq!(salt.len(), ARGON2ID_SALT_LEN);
    let ciphertext = data.get(VERSION.len() + ARGON2ID_SALT_LEN..).filter(|slice| slice.len() >= CHACHAPOLY_TAG_LEN).unwrap();
    assert_eq!(ciphertext.len(), CHACHAPOLY_TAG_LEN);
}

#[test]
fn decrypt5() {
    let data = hex::decode(format!("{}{}", SALT_HEX, TAG_HEX)).unwrap();
    let ciphertext = data.get(VERSION.len() + ARGON2ID_SALT_LEN..).filter(|slice| slice.len() >= CHACHAPOLY_TAG_LEN);
    assert!(matches!(ciphertext, None));
}

#[test]
fn combined1() {
    let password = hex::decode(PASSWORD_HEX).unwrap();
    let plaintext = hex::decode(PLAINTEXT_HEX).unwrap();
    let (salt, ciphertext) = encrypt_with_password(&password, &plaintext).unwrap();
    assert_eq!(ciphertext.len(), plaintext.len() + CHACHAPOLY_TAG_LEN);
    let mut ciphertext_combined = Vec::new();
    ciphertext_combined.extend_from_slice(&VERSION);
    ciphertext_combined.extend_from_slice(&salt);
    ciphertext_combined.extend_from_slice(&ciphertext);
    let plaintext2 = decrypt_with_password(&password, &salt,&ciphertext).unwrap();
    assert_eq!(plaintext, plaintext2);
}
