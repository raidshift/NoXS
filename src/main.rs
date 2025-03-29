use base64::prelude::*;
use noxs::*;
use std::{
    env,
    fs::{self, File},
    io::{self, IoSlice, Write},
    process::ExitCode,
};
use zeroize::Zeroize;

const COMMANDS: [&str; 4] = ["ea", "e", "da", "d"];

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

// const STD_ERR_FILE_NOT_FOUND: &str = "File not found";
const STD_ERR_PASSWORD_NO_MATCH: &str = "Passwords do not match";
const STD_ERR_EQUAL_OUT_IN: &str = "<out_file> must not be <in_file>";
const STD_ERR_EQUAL_PASSWD_IN_OUT: &str = "<passwd_file> must not be <in_file> or <out_file>";
const STD_OUT_ENTER_PASSWORD: &str = "Enter password:";
const STD_OUT_CONFIRM_PASSWORD: &str = "Confirm password:";
const STD_ERR_NOT_BASE64: &str = "Input data is not base64 encoded";
const STD_ERR_INVALID_CIPHER: &str = "Invalid cipher";

// fn exit_with_error(out: &str) -> ! {
//     eprintln!("{}", out);
//     std::process::exit(1);
// }

// fn read_data_from_file(path: &str) -> io::Result<Vec<u8>> {
//     fs::read(path)
// }

// fn write_io_slices_to_file(path: &str, io_slices: &[IoSlice]) -> io::Result<()> {
//     File::create(path)?.write_vectored(io_slices);
//     Ok(())
// }

// fn write_data_to_file(path: &str, data: &[u8]) -> io::Result<()> {
//     fs::write(path, data)
// }

fn query_password(prompt: &str) -> Vec<u8> {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    rpassword::read_password().unwrap().into_bytes()
}

fn main() -> ExitCode {
    let mut password: Vec<u8> = Vec::new();
    let mut password_confirm: Vec<u8> = Vec::new();
    let mut in_data: Vec<u8> = Vec::new();

    let result = run(&mut password, &mut password_confirm, &mut in_data);

    password.zeroize();
    password_confirm.zeroize();
    in_data.zeroize();

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
    in_data: &mut Vec<u8>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 || args.len() > 5 || !COMMANDS.contains(&args[1].as_str()) {
        return Err(STD_ERR_INFO.into());
    }

    let in_path = &args[2];
    let out_path = &args[3];

    if in_path == out_path {
        return Err(STD_ERR_EQUAL_OUT_IN.into());
    }

    let mut is_password_from_file = false;

    if args.len() == 5 {
        let passwd_path = &args[4];
        if passwd_path == in_path || passwd_path == out_path {
            return Err(STD_ERR_EQUAL_PASSWD_IN_OUT.into());
        }
        *password = fs::read(passwd_path)?;
        is_password_from_file = true;
    }

    *in_data = fs::read(in_path)?;
    let is_base64data;

    is_base64data = matches!(args[1].as_str(), "ea" | "da");

    match args[1].as_str() {
        "e" | "ea" => {
            if !is_password_from_file {
                *password = query_password(STD_OUT_ENTER_PASSWORD);
                *passworm_confirm = query_password(STD_OUT_CONFIRM_PASSWORD);
                if password != passworm_confirm {
                    return Err(STD_ERR_PASSWORD_NO_MATCH.into());
                }
            }

            let (salt, ciphertext) = encrypt_with_password(&password, &in_data)?;
            let mut file = File::create(out_path)?;

            match is_base64data {
                true => {
                    let mut combined = Vec::new();
                    combined.extend_from_slice(&[VERSION_BYTE]);
                    combined.extend_from_slice(&salt);
                    combined.extend_from_slice(&ciphertext);
                    file.write(BASE64_STANDARD.encode(combined).as_bytes())?;
                }
                false => {
                    file.write_vectored(&[
                        IoSlice::new(&[VERSION_BYTE]),
                        IoSlice::new(&salt),
                        IoSlice::new(&ciphertext),
                    ])?;
                }
            }
        }

        "d" | "da" => {
            if !is_password_from_file {
                *password = query_password(STD_OUT_ENTER_PASSWORD);
            }
            if is_base64data {
                *in_data = BASE64_STANDARD
                    .decode(&*in_data)
                    .map_err(|_| STD_ERR_NOT_BASE64)?;
            }

            in_data
                .get(..1)
                .filter(|&v| v == [VERSION_BYTE])
                .ok_or(STD_ERR_INVALID_CIPHER)?;

            let salt = in_data
                .get(1..1 + ARGON2ID_SALT_AND_XCHACHAPOLY_NONCE_LEN)
                .ok_or(STD_ERR_INVALID_CIPHER)?;
            let ciphertext = in_data
                .get(1 + ARGON2ID_SALT_AND_XCHACHAPOLY_NONCE_LEN..)
                .filter(|slice| slice.len() >= XCHACHAPOLY_TAG_LEN)
                .ok_or(STD_ERR_INVALID_CIPHER)?;

            let mut plaintext =
                decrypt_with_password(&password, salt.try_into().unwrap(), ciphertext)?;
            let mut file = File::create(out_path)?;
            file.write(&plaintext)?;
            plaintext.zeroize();
        }
        _ => {}
    }

    Ok(())
}
