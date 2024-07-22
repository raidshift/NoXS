use noxs::{decrypt_with_password, encrypt_with_password};

mod noxs;

fn main() {
    let password = "Hello";
    let plaintext = "top secret";
    let (key, salt) = noxs::derive_key_with_salt(&password);
    println!("key : {}",hex::encode(&key));
    println!("salt: {}",hex::encode(&salt));

    let ciphertext = encrypt_with_password(&password, plaintext.as_bytes());
    println!("ciph: {}",hex::encode(&ciphertext));

    let result = decrypt_with_password(&password, &ciphertext.to_vec());
    match result {
        Ok(plaintext) => {
            println!("{}",String::from_utf8_lossy(&plaintext))
        }
        Err(e) => panic!("{}", e.description()),
    }
}
