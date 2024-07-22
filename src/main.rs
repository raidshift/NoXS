mod noxs;


fn main() {
    let (key, salt) = noxs::derive_key_with_salt("Hello");
    noxs::print_hex(&key);
    println!();
    noxs::print_hex(&salt);
    println!();
}
