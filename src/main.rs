use noxs::{decrypt_with_password, encrypt_with_password};

mod noxs;

fn main() {
    let password = "Hello";
    let plaintext = "top secret";
    let (key, salt) = noxs::derive_key_with_salt(&password);
    noxs::print_hex(&key);
    println!();
    noxs::print_hex(&salt);
    println!();
    let ciphertext = encrypt_with_password(&password, plaintext.as_bytes());
    noxs::print_hex(&ciphertext);
    println!();

    let result = decrypt_with_password(&password, &ciphertext.to_vec());
    match result {
        Ok(plaintext) => {
            println!("{}",String::from_utf8_lossy(&plaintext))
        }
        Err(e) => panic!("{}", e.description()),
    }
}
