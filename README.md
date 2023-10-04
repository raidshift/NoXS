# NoXS
 
* Command Line Tool & Library for authenticated encryption with password-based key derivation
* Written in Swift (MacOS)
  
## Key derivation: Argon2id 
  * Parameters: iterations = 2, memory = 1024*256, parallelism = 2
  * Input: password, secure random salt (16 bytes)
  * Output: key (32 bytes)

## Authenticated encryption: ChaCha20-Poly1305
  * Input: key (32 bytes), nonce (last 12 bytes from salt), plaintext
  * Output: version 0x01 (1 byte) || salt (16 bytes) || ciphertext || authentication tag (16 bytes)
    ![image](https://github.com/raidshift/NoXS/assets/51262620/4e364805-0950-4c28-be78-daacc41b88e8)

## Usage
 
### With interaction (password prompt)
* noxs _command_ _in_file_ _out_file_
 
### Without interaction (password from file)
* noxs _command_ _in_file_ _out_file_ _password_file_
 
### Commands
* e = encrypt
* ea = encrypt & base64-encode
* d = decrypt
* da = base64-decode & decrypt
 
## Build with [SwiftPM](https://www.swift.org/install/) & install to /usr/local/bin
* build_install
