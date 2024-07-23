use argon2_kdf::{Algorithm, Hasher};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use core::panic;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub const VERSION: u8 = 1;
pub const VERSION_PREFIX_LEN: usize = 1;
pub const ARGON2ID_ITERATIONS: u32 = 2;
pub const ARGON2ID_MEMORY_MB: u32 = 256;
pub const ARGON2ID_PARALLELISM: u32 = 2;
pub const ARGON2ID_KEY_LEN: usize = 32;
pub const ARGON2ID_SALT_LEN: usize = 16;
pub const CHACHAPOLY_NONCE_LEN: usize = 12;
pub const CHACHAPOLY_TAG_LEN: usize = 16;

#[derive(Debug)]
pub enum NoXSErr {
    Format,
    Authentication,
    CoreCipher,
}

impl NoXSErr {
    pub fn description(&self) -> &str {
        match self {
            NoXSErr::Format => "Invalid input data",
            NoXSErr::Authentication => "Authentication failed",
            NoXSErr::CoreCipher => "Invoking cipher function failed",
        }
    }
}

pub fn derive_key(password: &[u8], salt: &[u8; ARGON2ID_SALT_LEN]) -> [u8; ARGON2ID_KEY_LEN] {
    let hash = Hasher::new()
        .algorithm(Algorithm::Argon2id)
        .custom_salt(salt)
        .hash_length(ARGON2ID_KEY_LEN.try_into().unwrap())
        .iterations(ARGON2ID_ITERATIONS)
        .memory_cost_kib(ARGON2ID_MEMORY_MB * 1024)
        .threads(ARGON2ID_PARALLELISM)
        .hash(password)
        .unwrap();

    hash.as_bytes().try_into().unwrap()
}

pub fn derive_key_with_salt(password: &[u8]) -> ([u8; ARGON2ID_KEY_LEN], [u8; ARGON2ID_SALT_LEN]) {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut salt = [0u8; ARGON2ID_SALT_LEN];

    rng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt);

    (key, salt)
}

pub fn encrypt(key: &[u8; ARGON2ID_KEY_LEN], salt: &[u8; ARGON2ID_SALT_LEN], plaintext: &[u8]) -> Vec<u8> {
    let chacha = ChaCha20Poly1305::new(Key::from_slice(key));
    let result = chacha.encrypt(Nonce::from_slice(&salt[ARGON2ID_SALT_LEN - CHACHAPOLY_NONCE_LEN..]), plaintext);

    match result {
        Ok(cipher) => {
            let mut ciphertext = vec![VERSION];
            ciphertext.extend_from_slice(salt);
            ciphertext.extend_from_slice(&cipher);
            ciphertext
        }
        Err(_) => panic!("{}", NoXSErr::CoreCipher.description()),
    }
}

pub fn encrypt_with_password(password: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let (key, salt) = derive_key_with_salt(password);
    encrypt(&key, &salt, plaintext)
}

pub fn decrypt(key: &[u8; ARGON2ID_KEY_LEN], ciphertext: &[u8]) -> Result<Vec<u8>, NoXSErr> {
    let nonce_start = VERSION_PREFIX_LEN + ARGON2ID_SALT_LEN - CHACHAPOLY_NONCE_LEN;
    let nonce = &ciphertext[nonce_start..nonce_start + CHACHAPOLY_NONCE_LEN];
    let chacha = ChaCha20Poly1305::new(Key::from_slice(key));

    chacha.decrypt(Nonce::from_slice(nonce), &ciphertext[nonce_start + CHACHAPOLY_NONCE_LEN..]).map_err(|_| NoXSErr::Authentication)
}

pub fn decrypt_with_password(password: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, NoXSErr> {
    println!("{} {}", ciphertext.len(), VERSION_PREFIX_LEN + ARGON2ID_SALT_LEN + CHACHAPOLY_TAG_LEN);
    if ciphertext.len() < VERSION_PREFIX_LEN + ARGON2ID_SALT_LEN + CHACHAPOLY_TAG_LEN || ciphertext[0] != VERSION {
        return Err(NoXSErr::Format);
    }

    let salt = &ciphertext[VERSION_PREFIX_LEN..VERSION_PREFIX_LEN + ARGON2ID_SALT_LEN];
    let key = derive_key(password, salt.try_into().unwrap());

    decrypt(&key, ciphertext)
}
