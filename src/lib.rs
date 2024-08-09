use std::{error::Error, fmt};

use argon2_kdf::{Algorithm, Hasher};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub const VERSION_BYTES: [u8; 1] = [1];
pub const ARGON2ID_ITERATIONS: u32 = 2;
pub const ARGON2ID_MEMORY_MB: u32 = 256;
pub const ARGON2ID_PARALLELISM: u32 = 2;
pub const ARGON2ID_KEY_LEN: usize = 32;
pub const ARGON2ID_SALT_LEN: usize = 16;
pub const CHACHAPOLY_NONCE_LEN: usize = 12;
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

pub fn derive_key(password: &[u8], salt: &[u8; ARGON2ID_SALT_LEN]) -> [u8; ARGON2ID_KEY_LEN] {
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

pub fn derive_key_with_salt(password: &[u8]) -> ([u8; ARGON2ID_KEY_LEN], [u8; ARGON2ID_SALT_LEN]) {
    let mut salt = [0u8; ARGON2ID_SALT_LEN];
    ChaCha20Rng::from_entropy().fill_bytes(&mut salt);
    let key = derive_key(password, &salt);
    (key, salt)
}

pub fn encrypt(
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

pub fn encrypt_with_password(
    password: &[u8],
    plaintext: &[u8],
) -> Result<([u8; ARGON2ID_SALT_LEN], Vec<u8>), CipherError> {
    let (key, salt) = &derive_key_with_salt(password);
    Ok((*salt, encrypt(key, salt, plaintext)?))
}

pub fn decrypt(
    key: &[u8; ARGON2ID_KEY_LEN],
    nonce: &[u8; CHACHAPOLY_NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CipherError> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(Nonce::from_slice(nonce), ciphertext)
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
