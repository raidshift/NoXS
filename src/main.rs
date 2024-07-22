use noxs::encrypt_with_password;

mod noxs;

fn main() {
    let password = "Hello";
    let plaintext = "top secret";
    let (key, salt) = noxs::derive_key_with_salt(&password);
    noxs::print_hex(&key);
    println!();
    noxs::print_hex(&salt);
    println!();
    let e = encrypt_with_password(&password, plaintext.as_bytes());
    noxs::print_hex(&e);
    println!();
}
