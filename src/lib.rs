use argon2_kdf::{Algorithm, Hasher};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::{error::Error, fmt};

pub const VERSION_ONE_BYTE: u8 = 0x01;
pub const VERSION_X_BYTE: u8 = 0x78;
const ARGON2ID_ITERATIONS: u32 = 2;
const ARGON2ID_MEMORY_MB: u32 = 256;
const ARGON2ID_PARALLELISM: u32 = 2;
const ARGON2ID_KEY_LEN: usize = 32;
pub const ARGON2ID_SALT_LEN: usize = 16;
pub const ARGON2ID_SALT_AND_XCHACHAPOLY_NONCE_LEN: usize = 24;
const CHACHAPOLY_NONCE_LEN: usize = 12;
pub const CHACHAPOLY_TAG_LEN: usize = 16;

#[derive(Debug)]
pub enum CipherError {
    DecryptionFailed,
    EncryptionFailed,
}

impl Error for CipherError {}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CipherError::DecryptionFailed => write!(f, "Decryption failed"),
            CipherError::EncryptionFailed => write!(f, "Encryption failed"),
        }
    }
}

fn derive_key(password: &[u8], salt: &[u8]) -> [u8; ARGON2ID_KEY_LEN] {
    Hasher::new()
        .algorithm(Algorithm::Argon2id)
        .custom_salt(salt)
        .hash_length(ARGON2ID_KEY_LEN.try_into().unwrap())
        .iterations(ARGON2ID_ITERATIONS)
        .memory_cost_kib(ARGON2ID_MEMORY_MB * 1024)
        .threads(ARGON2ID_PARALLELISM)
        .hash(password)
        .unwrap()
        .as_bytes()
        .try_into()
        .unwrap()
}

fn encrypt(
    key: &[u8; ARGON2ID_KEY_LEN],
    salt: &[u8; ARGON2ID_SALT_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CipherError> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(
            Nonce::from_slice(&salt[ARGON2ID_SALT_LEN - CHACHAPOLY_NONCE_LEN..]),
            plaintext,
        )
        .map_err(|_| CipherError::EncryptionFailed)
}

fn encrypt_x(
    key: &[u8; ARGON2ID_KEY_LEN],
    salt: &[u8; ARGON2ID_SALT_AND_XCHACHAPOLY_NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CipherError> {
    XChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(salt.into(), plaintext)
        .map_err(|_| CipherError::EncryptionFailed)
}

pub fn encrypt_with_password(
    password: &[u8],
    plaintext: &[u8],
) -> Result<([u8; ARGON2ID_SALT_LEN], Vec<u8>), CipherError> {
    let mut salt = [0u8; ARGON2ID_SALT_LEN];
    ChaCha20Rng::from_os_rng().fill_bytes(&mut salt);
    let key = derive_key(password, &salt);
    Ok((salt, encrypt(&key, &salt, plaintext)?))
}

pub fn encrypt_x_with_password(
    password: &[u8],
    plaintext: &[u8],
) -> Result<([u8; ARGON2ID_SALT_AND_XCHACHAPOLY_NONCE_LEN], Vec<u8>), CipherError> {
    let mut salt = [0u8; ARGON2ID_SALT_AND_XCHACHAPOLY_NONCE_LEN];
    ChaCha20Rng::from_os_rng().fill_bytes(&mut salt);
    let key = derive_key(password, &salt);
    Ok((salt, encrypt_x(&key, &salt, plaintext)?))
}

fn decrypt(
    key: &[u8; ARGON2ID_KEY_LEN],
    nonce: &[u8; CHACHAPOLY_NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CipherError> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| CipherError::DecryptionFailed)
}

fn decrypt_x(
    key: &[u8; ARGON2ID_KEY_LEN],
    nonce: &[u8; ARGON2ID_SALT_AND_XCHACHAPOLY_NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CipherError> {
    XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| CipherError::DecryptionFailed)
}

pub fn decrypt_with_password(
    password: &[u8],
    salt: &[u8; ARGON2ID_SALT_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CipherError> {
    decrypt(
        &derive_key(password, salt),
        salt[ARGON2ID_SALT_LEN - CHACHAPOLY_NONCE_LEN..]
            .try_into()
            .unwrap(),
        ciphertext,
    )
}

pub fn decrypt_x_with_password(
    password: &[u8],
    salt: &[u8; ARGON2ID_SALT_AND_XCHACHAPOLY_NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CipherError> {
    decrypt_x(&derive_key(password, salt), salt, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD_HEX: &str = "b102a3049c060f";
    const KEY_HEX: &str = "ba49c1d86ab3b281e3cafe626e84274d6600504ec8bb072149b356ce1faea48b";
    const PLAINTEXT_HEX: &str = "6de01091d749f189c4e25aa315b314aa";
    const VERSION_HEX: &str = "01";
    const SALT_HEX: &str = "01020304a71ea4bf40414e434bc54649";
    const TAG_HEX: &str = "adcacd100c31dc5b2fa4c1f4575e684f";
    const CIPHERTEXT_HEX: &str = "91352cd42cf496937b700a902c01d9d4adcacd100c31dc5b2fa4c1f4575e684f";
    const CIPHERTEXT_COMBINED_HEX: &str = "0101020304a71ea4bf40414e434bc5464991352cd42cf496937b700a902c01d9d4adcacd100c31dc5b2fa4c1f4575e684f";

    const X_KEY_HEX: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const X_SALT_HEX: &str = "404142434445464748494a4b4c4d4e4f5051525354555657";
    const X_PLAINTEXT_HEX: &str = "12345678";
    const X_CIPHERTEXT_HEX: &str = "e338258c10628e0f11382a0cd1617e8ad35b3f33";

    #[test]
    fn kdf1() {
        let password = hex::decode(PASSWORD_HEX).unwrap();
        let salt = hex::decode(SALT_HEX).unwrap();
        let key = derive_key(&password, &salt);
        assert_eq!(hex::encode(key), KEY_HEX);
    }

    #[test]
    fn kdf2() {
        let password = vec![];
        let salt = vec![0; 16];
        let key = derive_key(&password, &salt);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn encrypt1() {
        let key = hex::decode(KEY_HEX).unwrap();
        let salt = hex::decode(SALT_HEX).unwrap();
        let plaintext = hex::decode(PLAINTEXT_HEX).unwrap();
        let ciphertext: Vec<u8> = encrypt(
            &key.try_into().unwrap(),
            &salt.try_into().unwrap(),
            &plaintext,
        )
        .unwrap();
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
        data.get(..1)
            .filter(|&v| v == [VERSION_ONE_BYTE])
            .unwrap();
        let salt = data
            .get(1..1 + ARGON2ID_SALT_LEN)
            .unwrap();
        let ciphertext = data
            .get(1 + ARGON2ID_SALT_LEN..)
            .filter(|slice| slice.len() >= CHACHAPOLY_TAG_LEN)
            .unwrap();
        assert_eq!(hex::encode(ciphertext), CIPHERTEXT_HEX);
        let plaintext = decrypt(
            &key.try_into().unwrap(),
            salt[ARGON2ID_SALT_LEN - CHACHAPOLY_NONCE_LEN..]
                .try_into()
                .unwrap(),
            ciphertext,
        )
        .unwrap();
        assert_eq!(hex::encode(plaintext), PLAINTEXT_HEX);
    }

    #[test]
    fn decrypt2() {
        let password = hex::decode(PASSWORD_HEX).unwrap();
        let salt = hex::decode(SALT_HEX).unwrap();
        let ciphertext = hex::decode(CIPHERTEXT_HEX).unwrap();
        let plaintext =
            decrypt_with_password(&password, &salt.try_into().unwrap(), &ciphertext).unwrap();
        assert_eq!(hex::encode(plaintext), PLAINTEXT_HEX);
    }

    #[test]
    fn decrypt3() {
        let password = hex::decode(PASSWORD_HEX).unwrap();
        let data = hex::decode(format!("{}{}{}", VERSION_HEX, SALT_HEX, TAG_HEX)).unwrap();
        data.get(..1)
            .filter(|&v| v == [VERSION_ONE_BYTE])
            .unwrap();
        let salt = data
            .get(1..1 + ARGON2ID_SALT_LEN)
            .unwrap();
        let ciphertext = data
            .get(1 + ARGON2ID_SALT_LEN..)
            .filter(|slice| slice.len() >= CHACHAPOLY_TAG_LEN)
            .unwrap();
        let result = decrypt_with_password(&password, &salt.try_into().unwrap(), &ciphertext);
        assert!(matches!(result, Err(CipherError::DecryptionFailed)));
    }

    #[test]
    fn decrypt4() {
        let data = hex::decode(format!("ff{}{}", SALT_HEX, TAG_HEX)).unwrap();
        let version = data
            .get(..1)
            .filter(|&v| v == [VERSION_ONE_BYTE]);
        assert!(matches!(version, None));
        let salt = data
            .get(1..1 + ARGON2ID_SALT_LEN)
            .unwrap();
        assert_eq!(salt.len(), ARGON2ID_SALT_LEN);
        let ciphertext = data
            .get(1 + ARGON2ID_SALT_LEN..)
            .filter(|slice| slice.len() >= CHACHAPOLY_TAG_LEN)
            .unwrap();
        assert_eq!(ciphertext.len(), CHACHAPOLY_TAG_LEN);
    }

    #[test]
    fn decrypt5() {
        let data = hex::decode(format!("{}{}", SALT_HEX, TAG_HEX)).unwrap();
        let ciphertext = data
            .get(1 + ARGON2ID_SALT_LEN..)
            .filter(|slice| slice.len() >= CHACHAPOLY_TAG_LEN);
        assert!(matches!(ciphertext, None));
    }

    #[test]
    fn combined1() {
        let password = hex::decode(PASSWORD_HEX).unwrap();
        let plaintext = hex::decode(PLAINTEXT_HEX).unwrap();
        let (salt, ciphertext) = encrypt_with_password(&password, &plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + CHACHAPOLY_TAG_LEN);
        let mut ciphertext_combined = Vec::new();
        ciphertext_combined.extend_from_slice(&[VERSION_ONE_BYTE]);
        ciphertext_combined.extend_from_slice(&salt);
        ciphertext_combined.extend_from_slice(&ciphertext);
        let plaintext2 = decrypt_with_password(&password, &salt, &ciphertext).unwrap();
        assert_eq!(plaintext, plaintext2);
    }

    #[test]
    fn combinedx() {
        let key = hex::decode(X_KEY_HEX).unwrap();
        let salt = hex::decode(X_SALT_HEX).unwrap();
        let plaintext = hex::decode(X_PLAINTEXT_HEX).unwrap();
        let ciphertext: Vec<u8> = encrypt_x(
            &key.clone().try_into().unwrap(),
            &salt.clone().try_into().unwrap(),
            &plaintext,
        )
        .unwrap();

        assert_eq!(hex::encode(ciphertext.clone()), X_CIPHERTEXT_HEX);
        let plaintext2 = decrypt_x(
            &key.try_into().unwrap(),
            &salt.try_into().unwrap(),
            &ciphertext,
        )
        .unwrap();
        assert_eq!(hex::encode(plaintext2), X_PLAINTEXT_HEX);
    }
}
