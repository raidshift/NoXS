use base64::prelude::*;
use noxs::*;
use std::{
    env,
    error::Error,
    fs::{self, File},
    io::{self, IoSlice, Write},
};
use zeroize::Zeroize;

const STD_ERR_INFO: &str = "
      od$$$$oo      NoXS V1.2.4 (https://github.com/raidshift/noxs)
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
const STD_ERR_IN_FILE: &str = "Failed to read from <in_file>";
const STD_ERR_PW_IN_FILE: &str = "Failed to read from <passwd_file>";
const STD_ERR_OUT_FILE: &str = "Failed to write to <out_file>";
const STD_ERR_PASSWORD_NO_MATCH: &str = "Passwords do not match";
const STD_ERR_EQUAL_OUT_IN: &str = "<out_file> must not be <in_file>";
const STD_ERR_EQUAL_PASSWD_IN_OUT: &str = "<passwd_file> must not be <in_file> or <out_file>";
const STD_ERR_NOT_BASE64: &str = "Input data is not base64 encoded";
const STD_ERR_INVALID_CIPHER: &str = "Invalid cipher";

const STD_OUT_ENTER_PASSWORD: &str = "Enter password:";
const STD_OUT_CONFIRM_PASSWORD: &str = "Confirm password:";

enum Command {
    Encrypt,
    EncryptBase64,
    Decrypt,
    DecryptBase64,
}

impl Command {
    fn from_str(cmd: &str) -> Option<Self> {
        match cmd {
            "e" => Some(Command::Encrypt),
            "d" => Some(Command::Decrypt),
            "ea" => Some(Command::EncryptBase64),
            "da" => Some(Command::DecryptBase64),
            _ => None,
        }
    }
}

fn prompt_password(prompt: &str) -> Vec<u8> {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    rpassword::read_password().unwrap().into_bytes()
}

fn main() {
    let mut password: Vec<u8> = Vec::new();
    let mut password_confirmed: Vec<u8> = Vec::new();
    let mut cipher_data: Vec<u8> = Vec::new();

    let args: Vec<String> = env::args().collect();

    let command = (args.len() == 4 || args.len() == 5)
        .then(|| Command::from_str(&args[1]))
        .flatten()
        .ok_or_else(|| {
            eprintln!("{STD_ERR_INFO}");
            std::process::exit(1);
        })
        .unwrap();

    let result = run(
        &mut password,
        &mut password_confirmed,
        &mut cipher_data,
        command,
        &args[2],
        &args[3],
        args.get(4),
    );

    password.zeroize();
    password_confirmed.zeroize();
    cipher_data.zeroize();

    let _ = result.map_err(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
}

fn run(
    password: &mut Vec<u8>,
    password_confirmed: &mut Vec<u8>,
    cipher_data: &mut Vec<u8>,
    command: Command,
    in_file: &String,
    out_file: &String,
    pw_file: Option<&String>,
) -> std::result::Result<(), Box<dyn Error>> {
    if in_file == out_file {
        return Err(STD_ERR_EQUAL_OUT_IN.into());
    }

    match pw_file {
        Some(pw_file) => {
            if pw_file == in_file || pw_file == out_file {
                return Err(STD_ERR_EQUAL_PASSWD_IN_OUT.into());
            }
            *password =
                fs::read(pw_file).map_err(|_| format!("{} '{}'", STD_ERR_PW_IN_FILE, pw_file))?;
        }
        None => {
            *password = prompt_password(STD_OUT_ENTER_PASSWORD);
            if matches!(command, Command::Encrypt | Command::EncryptBase64) {
                *password_confirmed = prompt_password(STD_OUT_CONFIRM_PASSWORD);
                if password != password_confirmed {
                    return Err(STD_ERR_PASSWORD_NO_MATCH.into());
                }
            }
        }
    };

    *cipher_data = fs::read(in_file).map_err(|_| format!("{} '{}'", STD_ERR_IN_FILE, in_file))?;

    match command {
        Command::Encrypt | Command::EncryptBase64 => {
            let (salt, ciphertext) = encrypt_with_password(&password, &cipher_data)?;
            let mut file = File::create(out_file)
                .map_err(|_| format!("{} '{}'", STD_ERR_OUT_FILE, out_file))?;

            match command {
                Command::EncryptBase64 => {
                    let mut combined = Vec::new();
                    combined.extend_from_slice(&[VERSION_BYTE]);
                    combined.extend_from_slice(&salt);
                    combined.extend_from_slice(&ciphertext);
                    file.write(BASE64_STANDARD.encode(combined).as_bytes())
                        .map_err(|_| format!("{} '{}'", STD_ERR_OUT_FILE, out_file))?;
                }
                _ => {
                    file.write_vectored(&[
                        IoSlice::new(&[VERSION_BYTE]),
                        IoSlice::new(&salt),
                        IoSlice::new(&ciphertext),
                    ])
                    .map_err(|_| format!("{} '{}'", STD_ERR_OUT_FILE, out_file))?;
                }
            }
        }

        Command::Decrypt | Command::DecryptBase64 => {
            if matches!(command, Command::DecryptBase64) {
                *cipher_data = BASE64_STANDARD
                    .decode(&*cipher_data)
                    .map_err(|_| STD_ERR_NOT_BASE64)?;
            };

            cipher_data
                .get(..1)
                .filter(|&v| v == [VERSION_BYTE])
                .ok_or(STD_ERR_INVALID_CIPHER)?;

            let salt: &[u8; ARGON2ID_SALT_AND_XCHACHAPOLY_NONCE_LEN] = cipher_data
                .get(1..1 + ARGON2ID_SALT_AND_XCHACHAPOLY_NONCE_LEN)
                .ok_or(STD_ERR_INVALID_CIPHER)?
                .try_into()?;

            let ciphertext = cipher_data
                .get(1 + ARGON2ID_SALT_AND_XCHACHAPOLY_NONCE_LEN..)
                .filter(|slice| slice.len() >= XCHACHAPOLY_TAG_LEN)
                .ok_or(STD_ERR_INVALID_CIPHER)?;

            *cipher_data = decrypt_with_password(&password, salt, ciphertext)?;
            let mut file = File::create(out_file)
                .map_err(|_| format!("{} '{}'", STD_ERR_OUT_FILE, out_file))?;
            file.write(&cipher_data)
                .map_err(|_| format!("{} '{}'", STD_ERR_OUT_FILE, out_file))?;
        }
    }

    Ok(())
}
