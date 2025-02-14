# NoXS
 
* Command line tool & library for authenticated encryption with password-based key derivation
  
## Key derivation: Argon2id
  * Parameters: iterations = 2, memory = 1024*256, parallelism = 2
  * Input: password, secure random salt (16 bytes)
  * Output: key (32 bytes)

## Authenticated encryption: XChaCha20-Poly1305
  * Input: key (32 bytes), salt/nonce, plaintext (n bytes)
  * Output: version 0x78 (1 byte) || salt/nonce (24 bytes) || ciphertext (n bytes) || authentication tag (16 bytes)

![NoXS](https://github.com/user-attachments/assets/5325e558-85cc-42da-8e96-2eda66b8754c)

## Usage
 
### With interaction (password prompt)
* noxs _\<command>_ _\<in_file>_ _\<out_file>_
 
### Without interaction (password from file)
* noxs _\<command>_ _\<in_file>_ _\<out_file>_ _\<password_file>_
 
### Commands
* _e_ = encrypt
* _ea_ = encrypt & base64-encode
* _d_ = decrypt
* _da_ = base64-decode & decrypt

## Build with Rust and install to /usr/local/bin
* rust_build_install
