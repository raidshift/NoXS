use noxs::{decrypt_with_password, derive_key_with_salt, encrypt_with_password};

fn main() {
    let password = "Hello";
    let plaintext = "💖";
    let (key, salt) = derive_key_with_salt(&password);
    println!("key : {}",hex::encode(&key));
    println!("salt: {}",hex::encode(&salt));
    println!("plai: {}",hex::encode(&plaintext));

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
