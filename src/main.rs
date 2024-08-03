use base64::{engine::general_purpose, Engine};
use noxs::{decrypt_with_password, encrypt_with_password, CipherText};
use std::{env, fs, io};

const COMMANDS: [&str; 4] = ["ea", "e", "da", "d"];

const STD_ERR_INFO: &str = "
    od$$$$oo      NoXS V1.2.R (https://github.com/raidshift/noxs)
   $$*°  °?$$
  d$$      ?$b    Usage:
  d$b      d$b     noxs <cmd> <in_file> <out_file>
d$$$$$$$$$$$$$$o                      or
$$$$$$$$$$$$$$$$   noxs <cmd> <in_file> <out_file> <passw_file>
$$$$$$$  $$$$$$$
$$$$$$$  $$$$$$$  Commands:
$$$$$$$$$$$$$$$$    e = encrypt  |  ea = encrypt & base64-encode
?$$$$$$$$$$$$$$$    d = decrypt  |  da = base64-decode & decrypt
";

const STD_ERR_FILE_NOT_FOUND: &str = "File not found";
const STD_ERR_PASSWORD_NO_MATCH: &str = "Passwords do not match";
const STD_ERR_EQUAL_OUT_IN: &str = "<out_file> must not be <in_file>";
const STD_ERR_EQUAL_PASSWD_IN_OUT: &str = "<passwd_file> must not be <in_file> or <out_file>";
const STD_OUT_ENTER_PASSWORD: &str = "Enter password:";
const STD_OUT_CONFIRM_PASSWORD: &str = "Confirm password:";
const DATA_ERR_TEXT_FORMAT_BASE64: &str = "Input data is not base64 encoded";

fn exit_with_error(out: &str) -> ! {
    eprintln!("{}", out);
    std::process::exit(1);
}

fn read_file(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| {
        exit_with_error(&match e.kind() {
            io::ErrorKind::NotFound => format!("{} ({})", STD_ERR_FILE_NOT_FOUND, path),
            _ => e.to_string(),
        })
    })
}

fn write_file(path: &str, data: &[u8]) {
    fs::write(path, data).unwrap_or_else(|e| exit_with_error(&e.to_string()));
}

fn get_password(prompt: &str) -> Vec<u8> {
    print!("{}", prompt);
    io::Write::flush(&mut io::stdout()).unwrap_or_else(|e| exit_with_error(&e.to_string()));
    let password = rpassword::read_password().unwrap();
    password.into_bytes()
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 || args.len() > 5 || !COMMANDS.contains(&args[1].as_str()) {
        exit_with_error(STD_ERR_INFO);
    }

    let in_path = &args[2];
    let out_path = &args[3];

    if in_path == out_path {
        exit_with_error(STD_ERR_EQUAL_OUT_IN);
    }

    let mut password = Vec::new();
    let mut password_from_file = false;

    if args.len() == 5 {
        let passwd_path = &args[4];
        if passwd_path == in_path || passwd_path == out_path {
            exit_with_error(STD_ERR_EQUAL_PASSWD_IN_OUT);
        }
        password = read_file(passwd_path);
        password_from_file = true;
    }

    let mut data = read_file(in_path);
    let is_base64data;

    match args[1].as_str() {
        "ea" | "da" => is_base64data = true,
        _ => is_base64data = false,
    }

    match args[1].as_str() {
        "e" | "ea" => {
            let confirm_password;
            if !password_from_file {
                password = get_password(STD_OUT_ENTER_PASSWORD);
                confirm_password = get_password(STD_OUT_CONFIRM_PASSWORD);
                if password != confirm_password {
                    exit_with_error(STD_ERR_PASSWORD_NO_MATCH);
                }
            }

            encrypt_with_password(&password, &data)
                .map(|encrypted_data| {
                    if is_base64data {
                        write_file(out_path, &general_purpose::STANDARD.encode(&encrypted_data).as_bytes())
                    } else {
                        write_file(out_path, &encrypted_data)
                    }
                })
                .unwrap_or_else(|e| exit_with_error(&e.to_string()));
        }

        "d" | "da" => {
            if !password_from_file {
                password = get_password(STD_OUT_ENTER_PASSWORD);
            }
            if is_base64data {
                data = general_purpose::STANDARD.decode(data).unwrap_or_else(|_| exit_with_error(DATA_ERR_TEXT_FORMAT_BASE64));
            }
            CipherText::new(&data)
                .and_then(|ciphertext| decrypt_with_password(&password, &ciphertext))
                .map(|decrypted_data| write_file(&out_path, &decrypted_data))
                .unwrap_or_else(|e| exit_with_error(&e.to_string()));
        }
        _ => {}
    }
}
