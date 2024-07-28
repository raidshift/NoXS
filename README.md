# NoXS
 
* Command line tool & library for authenticated encryption with password-based key derivation
  
## Key derivation: Argon2id
  * Parameters: iterations = 2, memory = 1024*256, parallelism = 2
  * Input: password, secure random salt (16 bytes)
  * Output: key (32 bytes)

## Authenticated encryption: ChaCha20-Poly1305
  * Input: key (32 bytes), nonce (last 12 bytes from salt), plaintext (n bytes)
  * Output: version 0x01 (1 byte) || salt (16 bytes) || ciphertext (n bytes) || authentication tag (16 bytes)
    ![image](https://github.com/raidshift/NoXS/assets/51262620/4e364805-0950-4c28-be78-daacc41b88e8)

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

## OR build with Swift and install to /usr/local/bin
* swift_build_install_macos
* swift_build_install_linux
