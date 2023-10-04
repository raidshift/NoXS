# NoXS
 
* Swift library for authenticated encryption/decryption with password-based key derivation
* For command line file encryption with X refer to https://github.com/raidshift/xcli
  
## Key derivation: Argon2id 
  * Parameters: iterations = 2, memory = 1024*256, parallelism = 2
  * Input: password, secure random salt (16 bytes)
  * Output: key (32 bytes)

## Authenticated encryption/decryption: ChaCha20-Poly1305
  * Input: key (32 bytes), nonce (last 12 bytes from salt), plaintext
  * Output: version 0x01 (1 byte) || salt (16 bytes) || ciphertext || authentication tag (16 bytes)

## Usage
 
### with interaction (password prompt)
* x _command_ _in_file_ _out_file_
 
### without interaction (password from file)
* x _command_ _in_file_ _out_file_ _password_file_
 
### commands
* e = encrypt
* ea = encrypt & base64-encode
* d = decrypt
* da = base64-decode & decrypt
 
## Build with [SwiftPM](https://www.swift.org/install/) & install to /usr/local/bin
* build_install