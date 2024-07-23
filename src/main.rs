use noxs::{decrypt_with_password, derive_key_with_salt, encrypt_with_password};

fn main() {
    let password = "Hello".as_bytes();
    let plaintext = "💖".as_bytes();

    let (key, salt) = derive_key_with_salt(&password);
    println!("key : {}", hex::encode(&key));
    println!("salt: {}", hex::encode(&salt));
    println!("plai: {}", hex::encode(&plaintext));

    let ciphertext = encrypt_with_password(&password, plaintext).unwrap();
    println!("ciph: {}", hex::encode(&ciphertext));

    let plaintext = decrypt_with_password(&password, &ciphertext.to_vec()).unwrap();
    println!("{}", String::from_utf8_lossy(&plaintext))
}
