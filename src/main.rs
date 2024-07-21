mod noxs;

fn print_hex(bytes: &[u8]) {
    for byte in bytes {
        print!("{:02x}", byte);
    }
}


fn main() {
    let (key, salt) = noxs::derive_key_with_salt("Hello");
    print_hex(&key);
    println!();
    print_hex(&salt);
    println!();
}
