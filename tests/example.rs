// use noxs::*;

const PASSWORD_HEX: &str = "b102a3049c060f";
const KEY_HEX: &str = "ba49c1d86ab3b281e3cafe626e84274d6600504ec8bb072149b356ce1faea48b";
const PLAINTEXT_HEX: &str = "6de01091d749f189c4e25aa315b314aa";
const NONCE_HEX: &str = "a71ea4bf40414e434bc54649";
const VERSION_HEX: &str = "01";
const SALT_HEX: &str = "01020304a71ea4bf40414e434bc54649";
const ENCRYPTED_HEX: &str = "91352cd42cf496937b700a902c01d9d4";
const TAG_HEX: &str = "adcacd100c31dc5b2fa4c1f4575e684f";
const CIPHERTEXT_HEX: &str = "0101020304a71ea4bf40414e434bc5464991352cd42cf496937b700a902c01d9d4adcacd100c31dc5b2fa4c1f4575e684f";

#[test]
fn test_key_derivation() {
    println!("Password Hex: {}", PASSWORD_HEX);
    println!("Key Hex: {}", KEY_HEX);
    println!("Plaintext Hex: {}", PLAINTEXT_HEX);
    println!("Nonce Hex: {}", NONCE_HEX);
    println!("Version Hex: {}", VERSION_HEX);
    println!("Salt Hex: {}", SALT_HEX);
    println!("Encrypted Hex: {}", ENCRYPTED_HEX);
    println!("Tag Hex: {}", TAG_HEX);
    println!("Ciphertext Hex: {}", CIPHERTEXT_HEX);

    println!("{:?}", hex::decode(PASSWORD_HEX));
}
