use base64::prelude::*;
use noxs::{
    decrypt_with_password, encrypt_with_password, ARGON2ID_SALT_LEN, CHACHAPOLY_TAG_LEN,
    VERSION_BYTES,
};
use std::{
    env,
    fs::{self, File},
    io::{self, IoSlice, Write},
};

const COMMANDS: [&str; 4] = ["ea", "e", "da", "d"];

const STD_ERR_INFO: &str = "
      od$$$$oo      NoXS V1.2.R (https://github.com/raidshift/noxs)
     $$*°  °?$$
    d$$      ?$b    Usage:
    d$b      d$b      noxs <cmd> <in_file> <out_file>
  d$$$$$$$$$$$$$$o                      or
  $$$$$$$$$$$$$$$$    noxs <cmd> <in_file> <out_file> <passw_file>
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
const STD_ERR_NOT_BASE64: &str = "Input data is not base64 encoded";
const STD_ERR_INVALID_CIPHER: &str = "Invalid cipher";

fn exit_with_error(out: &str) -> ! {
    eprintln!("{}", out);
    std::process::exit(1);
}

fn read_data_from_file(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| {
        exit_with_error(&match e.kind() {
            io::ErrorKind::NotFound => format!("{} ({})", STD_ERR_FILE_NOT_FOUND, path),
            _ => e.to_string(),
        })
    })
}

fn write_io_slices_to_file(path: &str, io_slices: &[IoSlice]) {
    let mut file = File::create(path).unwrap_or_else(|e| exit_with_error(&e.to_string()));

    file.write_vectored(io_slices)
        .unwrap_or_else(|e| exit_with_error(&e.to_string()));
}

fn write_data_to_file(path: &str, data: &[u8]) {
    fs::write(path, data).unwrap_or_else(|e| exit_with_error(&e.to_string()));
}

fn query_password(prompt: &str) -> Vec<u8> {
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
        password = read_data_from_file(passwd_path);
        password_from_file = true;
    }

    let mut in_data = read_data_from_file(in_path);
    let is_base64data;

    is_base64data = matches!(args[1].as_str(), "ea" | "da");

    match args[1].as_str() {
        "e" | "ea" => {
            let confirm_password;
            if !password_from_file {
                password = query_password(STD_OUT_ENTER_PASSWORD);
                confirm_password = query_password(STD_OUT_CONFIRM_PASSWORD);
                if password != confirm_password {
                    exit_with_error(STD_ERR_PASSWORD_NO_MATCH);
                }
            }

            encrypt_with_password(&password, &in_data)
                .map(|(salt, ciphertext)| {
                    if is_base64data {
                        let mut combined = Vec::new();
                        combined.extend_from_slice(&VERSION_BYTES);
                        combined.extend_from_slice(&salt);
                        combined.extend_from_slice(&ciphertext);

                        write_data_to_file(out_path, BASE64_STANDARD.encode(combined).as_bytes())
                    } else {
                        write_io_slices_to_file(
                            out_path,
                            &[
                                IoSlice::new(&VERSION_BYTES),
                                IoSlice::new(&salt),
                                IoSlice::new(&ciphertext),
                            ],
                        )
                    }
                })
                .unwrap_or_else(|e| exit_with_error(&e.to_string()));
        }

        "d" | "da" => {
            if !password_from_file {
                password = query_password(STD_OUT_ENTER_PASSWORD);
            }
            if is_base64data {
                in_data = BASE64_STANDARD
                    .decode(in_data)
                    .unwrap_or_else(|_| exit_with_error(STD_ERR_NOT_BASE64));
            }

            in_data
                .get(..VERSION_BYTES.len())
                .filter(|&v| v == &VERSION_BYTES[..])
                .unwrap_or_else(|| exit_with_error(STD_ERR_INVALID_CIPHER));
            let salt = in_data
                .get(VERSION_BYTES.len()..VERSION_BYTES.len() + ARGON2ID_SALT_LEN)
                .unwrap_or_else(|| exit_with_error(STD_ERR_INVALID_CIPHER));
            let ciphertext = in_data
                .get(VERSION_BYTES.len() + ARGON2ID_SALT_LEN..)
                .filter(|slice| slice.len() >= CHACHAPOLY_TAG_LEN)
                .unwrap_or_else(|| exit_with_error(STD_ERR_INVALID_CIPHER));

            decrypt_with_password(&password, salt.try_into().unwrap(), ciphertext)
                .map(|plaintext| write_data_to_file(&out_path, &plaintext))
                .unwrap_or_else(|e| exit_with_error(&e.to_string()));
        }
        _ => {}
    }
}
