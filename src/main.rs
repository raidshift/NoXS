use base64::prelude::*;
use noxs::*;
use std::{
    env,
    fs::{self, File},
    io::{self, IoSlice, Write},
    process::ExitCode,
};
use zeroize::Zeroize;

const STD_ERR_INFO: &str = "
      od$$$$oo      NoXS V1.2.3 (https://github.com/raidshift/noxs)
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

fn main() -> ExitCode {
    let mut password: Vec<u8> = Vec::new();
    let mut password_confirm: Vec<u8> = Vec::new();
    let mut cipher_data: Vec<u8> = Vec::new();

    let result = run(&mut password, &mut password_confirm, &mut cipher_data);

    password.zeroize();
    password_confirm.zeroize();
    cipher_data.zeroize();

    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{}", e);
            ExitCode::FAILURE
        }
    }
}

fn run(
    password: &mut Vec<u8>,
    passworm_confirm: &mut Vec<u8>,
    cipher_data: &mut Vec<u8>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 || args.len() > 5 {
        return Err(STD_ERR_INFO.into());
    }

    let command = Command::from_str(&args[1]).ok_or_else(|| STD_ERR_INFO)?;

    let in_path = &args[2];
    let out_path = &args[3];

    if in_path == out_path {
        return Err(STD_ERR_EQUAL_OUT_IN.into());
    }

    let mut is_password_from_file = false;

    if args.len() == 5 {
        let in_pw_path = &args[4];
        if in_pw_path == in_path || in_pw_path == out_path {
            return Err(STD_ERR_EQUAL_PASSWD_IN_OUT.into());
        }
        *password =
            fs::read(in_pw_path).map_err(|_| format!("{} '{}'", STD_ERR_PW_IN_FILE, in_pw_path))?;
        is_password_from_file = true;
    }

    *cipher_data = fs::read(in_path).map_err(|_| format!("{} '{}'", STD_ERR_IN_FILE, in_path))?;
    let is_base64data = matches!(command, Command::EncryptBase64 | Command::DecryptBase64);

    match command {
        Command::Encrypt | Command::EncryptBase64 => {
            if !is_password_from_file {
                *password = prompt_password(STD_OUT_ENTER_PASSWORD);
                *passworm_confirm = prompt_password(STD_OUT_CONFIRM_PASSWORD);
                if password != passworm_confirm {
                    return Err(STD_ERR_PASSWORD_NO_MATCH.into());
                }
            }

            let (salt, ciphertext) = encrypt_with_password(&password, &cipher_data)?;
            let mut file = File::create(out_path)
                .map_err(|_| format!("{} '{}'", STD_ERR_OUT_FILE, out_path))?;

            match is_base64data {
                true => {
                    let mut combined = Vec::new();
                    combined.extend_from_slice(&[VERSION_BYTE]);
                    combined.extend_from_slice(&salt);
                    combined.extend_from_slice(&ciphertext);
                    file.write(BASE64_STANDARD.encode(combined).as_bytes())
                        .map_err(|_| format!("{} '{}'", STD_ERR_OUT_FILE, out_path))?;
                }
                false => {
                    file.write_vectored(&[
                        IoSlice::new(&[VERSION_BYTE]),
                        IoSlice::new(&salt),
                        IoSlice::new(&ciphertext),
                    ])
                    .map_err(|_| format!("{} '{}'", STD_ERR_OUT_FILE, out_path))?;
                }
            }
        }

        Command::Decrypt | Command::DecryptBase64 => {
            if !is_password_from_file {
                *password = prompt_password(STD_OUT_ENTER_PASSWORD);
            }
            if is_base64data {
                *cipher_data = BASE64_STANDARD
                    .decode(&*cipher_data)
                    .map_err(|_| STD_ERR_NOT_BASE64)?;
            }

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
            let mut file = File::create(out_path)
                .map_err(|_| format!("{} '{}'", STD_ERR_OUT_FILE, out_path))?;
            file.write(&cipher_data)
                .map_err(|_| format!("{} '{}'", STD_ERR_OUT_FILE, out_path))?;
        }
    }

    Ok(())
}
