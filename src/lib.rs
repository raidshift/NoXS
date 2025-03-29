use argon2_kdf::{Algorithm, Hasher};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::{error::Error, fmt, ptr};
use zeroize::Zeroize;

pub const VERSION_BYTE: u8 = 0x78;
const ARGON2ID_ITERATIONS: u32 = 2;
const ARGON2ID_MEMORY_MB: u32 = 256;
const ARGON2ID_PARALLELISM: u32 = 2;
const ARGON2ID_KEY_LEN: usize = 32;
pub const ARGON2ID_SALT_AND_XCHACHAPOLY_NONCE_LEN: usize = 24;
pub const XCHACHAPOLY_TAG_LEN: usize = 16;

#[derive(Debug)]
pub enum CipherError {
    Decrypt,
    Encrypt,
    Rng,
    DeriveKey,
}

impl Error for CipherError {}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CipherError::Decrypt => write!(f, "Decryption failed"),
            CipherError::Encrypt => write!(f, "Encryption failed"),
            CipherError::Rng => write!(f, "Random number generation failed"),
            CipherError::DeriveKey => write!(f, "Key derivation failed"),
        }
    }
}

fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; ARGON2ID_KEY_LEN], CipherError> {
    let hash = Hasher::new()
        .algorithm(Algorithm::Argon2id)
        .custom_salt(salt)
        .hash_length(ARGON2ID_KEY_LEN.try_into().unwrap())
        .iterations(ARGON2ID_ITERATIONS)
        .memory_cost_kib(ARGON2ID_MEMORY_MB * 1024)
        .threads(ARGON2ID_PARALLELISM)
        .hash(password)
        .map_err(|_| CipherError::DeriveKey)?;

    let key: Result<[u8; ARGON2ID_KEY_LEN],CipherError> = hash
        .as_bytes()
        .try_into().map_err(|_| CipherError::DeriveKey);

    let ptr = hash.as_bytes().as_ptr() as *mut u8;
    let len = hash.as_bytes().len();

    unsafe {
        for i in 0..len {
            ptr::write_volatile(ptr.add(i), 0);
        }
    }
    
    key
}

fn encrypt(
    key: &[u8; ARGON2ID_KEY_LEN],
    salt: &[u8; ARGON2ID_SALT_AND_XCHACHAPOLY_NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CipherError> {
    XChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(salt.into(), plaintext)
        .map_err(|_| CipherError::Encrypt)
}

pub fn encrypt_with_password(
    password: &[u8],
    plaintext: &[u8],
) -> Result<([u8; ARGON2ID_SALT_AND_XCHACHAPOLY_NONCE_LEN], Vec<u8>), CipherError> {
    let mut rng = ChaCha20Rng::try_from_os_rng().map_err(|_| CipherError::Rng)?;
    let mut salt = [0u8; ARGON2ID_SALT_AND_XCHACHAPOLY_NONCE_LEN];
    rng.fill_bytes(&mut salt);
    let mut key = derive_key(password, &salt)?;
    let result = encrypt(&key, &salt, plaintext);
    key.zeroize();
    let encrypted = result?;
    Ok((salt, encrypted))
}

fn decrypt(
    key: &[u8; ARGON2ID_KEY_LEN],
    nonce: &[u8; ARGON2ID_SALT_AND_XCHACHAPOLY_NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CipherError> {
    XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| CipherError::Decrypt)
}

pub fn decrypt_with_password(
    password: &[u8],
    salt: &[u8; ARGON2ID_SALT_AND_XCHACHAPOLY_NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CipherError> {
    let mut key = derive_key(password, salt)?;
    let decrypted = decrypt(&key, salt, ciphertext);
    key.zeroize();
    decrypted
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD_HEX: &str = "b102a3049c060f";
    const KEY_HEX: &str = "ba49c1d86ab3b281e3cafe626e84274d6600504ec8bb072149b356ce1faea48b";
    const SALT_HEX: &str = "01020304a71ea4bf40414e434bc54649";
    const X_KEY_HEX: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const X_SALT_HEX: &str = "404142434445464748494a4b4c4d4e4f5051525354555657";
    const X_PLAINTEXT_HEX: &str = "12345678";
    const X_CIPHERTEXT_HEX: &str = "e338258c10628e0f11382a0cd1617e8ad35b3f33";

    #[test]
    fn kdf() {
        let password = hex::decode(PASSWORD_HEX).unwrap();
        let salt = hex::decode(SALT_HEX).unwrap();
        let key = derive_key(&password, &salt).unwrap();
        assert_eq!(hex::encode(key), KEY_HEX);
    }

    #[test]
    fn combined() {
        let key = hex::decode(X_KEY_HEX).unwrap();
        let salt = hex::decode(X_SALT_HEX).unwrap();
        let plaintext = hex::decode(X_PLAINTEXT_HEX).unwrap();
        let ciphertext: Vec<u8> = encrypt(
            &key.clone().try_into().unwrap(),
            &salt.clone().try_into().unwrap(),
            &plaintext,
        )
        .unwrap();

        assert_eq!(hex::encode(ciphertext.clone()), X_CIPHERTEXT_HEX);
        let plaintext2 = decrypt(
            &key.try_into().unwrap(),
            &salt.try_into().unwrap(),
            &ciphertext,
        )
        .unwrap();
        assert_eq!(hex::encode(plaintext2), X_PLAINTEXT_HEX);
    }
}
