import argon2
import CryptoKit
import Foundation

let VERSION = UInt8(1)

let VERSION_PREFIX_LEN = 1

let ARGON2ID_VERSION = 0x13
let ARGON2ID_ITERATIONS = UInt8(2)
let ARGON2ID_MEMORY_MB = UInt16(256)
let ARGON2ID_PARALLELISM = UInt8(2)
let ARGON2ID_KEY_LEN = 32
let ARGON2ID_SALT_LEN = 16

let CHACHAPOLY_NONCE_LEN = 12
let CHACHAPOLY_TAG_LEN = 16

public enum NOXS_ERR: Error {
    case FORMAT
    case AUTHENTICATION
    case CORE_RND
    case CORE_KDF
    case CORE_CIPHER
}

let ENCRYPT_ERR_TEXT_FORMAT = "Invalid input data"
let ENCRYPT_ERR_TEXT_AUTHENTICATION = "Authentication failed"
let ENCRYPT_ERR_CORE_RND = "Invoking secure random number generator failed"
let ENCRYPT_ERR_CORE_KDF = "Invoking key derivation function failed"
let ENCRYPT_ERR_CORE_CIPHER = "Invoking cipher function failed"

extension NOXS_ERR: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .FORMAT:
            return NSLocalizedString(ENCRYPT_ERR_TEXT_FORMAT, comment: ENCRYPT_ERR_TEXT_FORMAT)
        case .AUTHENTICATION:
            return NSLocalizedString(ENCRYPT_ERR_TEXT_AUTHENTICATION, comment: ENCRYPT_ERR_TEXT_AUTHENTICATION)
        case .CORE_RND:
            return NSLocalizedString(ENCRYPT_ERR_CORE_RND, comment: ENCRYPT_ERR_CORE_RND)
        case .CORE_KDF:
            return NSLocalizedString(ENCRYPT_ERR_CORE_KDF, comment: ENCRYPT_ERR_CORE_KDF)
        case .CORE_CIPHER:
            return NSLocalizedString(ENCRYPT_ERR_CORE_CIPHER, comment: ENCRYPT_ERR_CORE_CIPHER)
        }
    }
}

public func deriveKey(password: inout Data, salt: inout Data) throws -> Data {
    if salt.count != ARGON2ID_SALT_LEN { throw NOXS_ERR.FORMAT }

    var key = Data(repeating: 0, count: ARGON2ID_KEY_LEN)

    try key.withUnsafeMutableBytes { keyBytes in
        try salt.withUnsafeBytes { saltBytes in
            try password.withUnsafeBytes { passwordBytes in
                if argon2_hash(
                    UInt32(ARGON2ID_ITERATIONS),
                    1024 * UInt32(ARGON2ID_MEMORY_MB),
                    UInt32(ARGON2ID_PARALLELISM),
                    passwordBytes.baseAddress!,
                    password.count, saltBytes.baseAddress!,
                    ARGON2ID_SALT_LEN, keyBytes.baseAddress!,
                    ARGON2ID_KEY_LEN,
                    nil,
                    0,
                    Argon2_id,
                    UInt32(ARGON2ID_VERSION)
                ) != 0 { throw NOXS_ERR.CORE_KDF }
            }
        }
    }

    return key
}

public func deriveKey(password: inout Data) throws -> (key: Data, salt: Data) {
    var salt = Data(repeating: 0, count: ARGON2ID_SALT_LEN)

    try salt.withUnsafeMutableBytes { saltBytes in
        if SecRandomCopyBytes(kSecRandomDefault, ARGON2ID_SALT_LEN, saltBytes.baseAddress!) != 0 { throw NOXS_ERR.CORE_RND }
    }

    return try (key: deriveKey(password: &password, salt: &salt), salt: salt)
}

public func encrypt(key: inout Data, salt: inout Data, plaintext: inout Data) throws -> Data {
    if key.count != ARGON2ID_KEY_LEN || salt.count != ARGON2ID_SALT_LEN { throw NOXS_ERR.FORMAT }

    do {
        return try
            Data([VERSION])
            + salt.subdata(in: 0 ..< ARGON2ID_SALT_LEN - CHACHAPOLY_NONCE_LEN)
            + ChaChaPoly.seal(
                plaintext,
                using: SymmetricKey(data: key),
                nonce: ChaChaPoly.Nonce(data: salt.subdata(in: ARGON2ID_SALT_LEN - CHACHAPOLY_NONCE_LEN ..< ARGON2ID_SALT_LEN))
            ).combined
    } catch {
        throw NOXS_ERR.CORE_CIPHER
    }
}

public func encrypt(password: inout Data, plaintext: inout Data) throws -> Data {
    var key = try deriveKey(password: &password)

    return try encrypt(key: &key.key, salt: &key.salt, plaintext: &plaintext)
}

public func decrypt(key: inout Data, ciphertext: inout Data) throws -> Data {
    if key.count != ARGON2ID_KEY_LEN { throw NOXS_ERR.FORMAT }

    do {
        return try ciphertext.withUnsafeMutableBytes { cipherBytes in
            try ChaChaPoly.open(
                ChaChaPoly.SealedBox(
                    combined: Data(
                        bytesNoCopy: cipherBytes.baseAddress! + VERSION_PREFIX_LEN + ARGON2ID_SALT_LEN - CHACHAPOLY_NONCE_LEN,
                        count: cipherBytes.count - (VERSION_PREFIX_LEN + ARGON2ID_SALT_LEN - CHACHAPOLY_NONCE_LEN),
                        deallocator: .none
                    )),
                using: SymmetricKey(data: key)
            )
        }
    } catch CryptoKitError.authenticationFailure {
        throw NOXS_ERR.AUTHENTICATION
    } catch {
        throw NOXS_ERR.CORE_CIPHER
    }
}

public func decrypt(password: inout Data, ciphertext: inout Data) throws -> Data {
    if ciphertext.count < VERSION_PREFIX_LEN + ARGON2ID_SALT_LEN + CHACHAPOLY_TAG_LEN || ciphertext[0] != VERSION { throw NOXS_ERR.FORMAT }

    var salt = ciphertext.withUnsafeMutableBytes { cipherBytes in
        Data(bytesNoCopy: cipherBytes.baseAddress! + VERSION_PREFIX_LEN, count: ARGON2ID_SALT_LEN, deallocator: .none)
    }

    var key = try deriveKey(password: &password, salt: &salt)

    return try decrypt(key: &key, ciphertext: &ciphertext)
}
