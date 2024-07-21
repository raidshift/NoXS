use argon2_kdf::{Algorithm, Hasher};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

// const VERSION: u8 = 1;
// const VERSION_PREFIX_LEN: usize = 1;
const ARGON2ID_ITERATIONS: u32 = 2;
const ARGON2ID_MEMORY_MB: u32 = 256;
const ARGON2ID_PARALLELISM: u32 = 2;
const ARGON2ID_KEY_LEN: usize = 32;
const ARGON2ID_SALT_LEN: usize = 16;
// const CHACHAPOLY_NONCE_LEN: usize = 12;
// const CHACHAPOLY_TAG_LEN: usize = 16;

// #[derive(Debug)]
// pub enum NoXSErr {
//     Format,
//     Authentication,
//     CoreRnd,
//     CoreKdf,
//     CoreCipher,
// }

// impl NoXSErr {
//     fn description(&self) -> &str {
//         match self {
//             NoXSErr::Format => "Invalid input data",
//             NoXSErr::Authentication => "Authentication failed",
//             NoXSErr::CoreRnd => "Invoking secure random number generator failed",
//             NoXSErr::CoreKdf => "Invoking key derivation function failed",
//             NoXSErr::CoreCipher => "Invoking cipher function failed",
//         }
//     }
// }

pub fn derive_key(password: &str, salt: &[u8; ARGON2ID_SALT_LEN]) -> [u8; ARGON2ID_KEY_LEN] {
    let hash = Hasher::new()
        .algorithm(Algorithm::Argon2id)
        .custom_salt(salt)
        .hash_length(ARGON2ID_KEY_LEN.try_into().unwrap())
        .iterations(ARGON2ID_ITERATIONS)
        .memory_cost_kib(ARGON2ID_MEMORY_MB * 1024)
        .threads(ARGON2ID_PARALLELISM)
        .hash(password.as_bytes())
        .unwrap();

    hash.as_bytes().try_into().unwrap()
}

pub fn derive_key_with_salt(password: &str) -> ([u8; ARGON2ID_KEY_LEN], [u8; ARGON2ID_SALT_LEN]) {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut salt = [0u8; ARGON2ID_SALT_LEN];

    rng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt);
    (key, salt)
}
