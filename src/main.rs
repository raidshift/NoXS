use noxs::{decrypt_with_password, derive_key_with_salt, encrypt_with_password};

const COMMANDS: [&str; 4] = ["ea", "e", "da", "d"];

const STD_ERR_INFO: &str = "

NoXS V1.2.R  (https://github.com/raidshift/noxs)

Usage:
   noxs <cmd> <in_file> <out_file>
                     or
   noxs <cmd> <in_file> <out_file> <passw_file>

Commands:
   e = encrypt  |  ea = encrypt & base64-encode
   d = decrypt  |  da = base64-decode & decrypt

";

const STD_ERR_PASSWORD_NO_MATCH: &str = "Passwords do not match";
const STD_ERR_EQUAL_OUT_IN: &str = "<out_file> must not be <in_file>";
const STD_ERR_EQUAL_PASSWD_OUT: &str = "<passwd_file> must not be <out_file>";
const STD_OUT_ENTER_PASSWORD: &str = "Enter password:";
const STD_OUT_CONFIRM_PASSWORD: &str = "Confirm password:";
const DATA_ERR_TEXT_FORMAT_BASE64: &str = "Input data is not base64 encoded";

fn exit_with_error(out: &str) -> ! {
    eprintln!("{}", out);
    std::process::exit(1);
}

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
