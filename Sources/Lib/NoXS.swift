import argon2
import Crypto
import CryptoSwift
import Foundation

// let VERSION_ONE: UInt8 = UInt8(1)
// let VERSION_X: UInt8 = 0x78

let VERSION_PREFIX_LEN = 1

let ARGON2ID_VERSION = 0x13
let ARGON2ID_ITERATIONS = UInt8(2)
let ARGON2ID_MEMORY_MB = UInt16(256)
let ARGON2ID_PARALLELISM = UInt8(2)
let ARGON2ID_KEY_LEN = 32
// let ARGON2ID_SALT_LEN_VERSION_ONE = 16
// let ARGON2ID_SALT_LEN_VERSION_X = 24

// let CHACHAPOLY_NONCE_LEN_VERSION_ONE = 12
let CHACHAPOLY_TAG_LEN = 16

public enum NOXS_VER {
    case ONE
    case X
}

public extension NOXS_VER {
    var VERSION_BYTE: UInt8 {
        switch self {
        case .ONE: return UInt8(1)
        case .X: return 0x78
        }
    }

    var ARGON2ID_SALT_LEN: Int {
        switch self {
        case .ONE: return 16
        case .X: return 24
        }
    }

    var CHACHAPOLY_NONCE_LEN: Int {
        switch self {
        case .ONE: return 12
        case .X: return 24
        }
    }
}

public enum NOXS_ERR: Error {
    case FORMAT
    case CORE_KDF
    case CORE_CIPHER
}

let ENCRYPT_ERR_TEXT_FORMAT = "Invalid input data"
let ENCRYPT_ERR_CORE_KDF = "Invoking key derivation function failed"
let ENCRYPT_ERR_CORE_CIPHER = "Invoking cipher function failed"

extension NOXS_ERR: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .FORMAT:
            return NSLocalizedString(ENCRYPT_ERR_TEXT_FORMAT, comment: ENCRYPT_ERR_TEXT_FORMAT)
        case .CORE_KDF:
            return NSLocalizedString(ENCRYPT_ERR_CORE_KDF, comment: ENCRYPT_ERR_CORE_KDF)
        case .CORE_CIPHER:
            return NSLocalizedString(ENCRYPT_ERR_CORE_CIPHER, comment: ENCRYPT_ERR_CORE_CIPHER)
        }
    }
}

public func deriveKey(password: inout Data, salt: inout Data) throws -> Data {
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
                    salt.count, keyBytes.baseAddress!,
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

public func deriveKey(password: inout Data, ver: NOXS_VER) throws -> (key: Data, salt: Data) {
    var rndGen = SystemRandomNumberGenerator()
    var rndData = Data()

    for _ in 1 ... 1 + ver.ARGON2ID_SALT_LEN / MemoryLayout<UInt64>.size {
        var rnd = rndGen.next()
        rndData += Data(bytes: &rnd, count: MemoryLayout<UInt64>.size)
    }

    var salt = rndData.subdata(in: 0 ..< ver.ARGON2ID_SALT_LEN)

    return try (key: deriveKey(password: &password, salt: &salt), salt: salt)
}

public func encrypt(key: inout Data, salt: inout Data, plaintext: inout Data, ver: NOXS_VER) throws -> Data {
    if key.count != ARGON2ID_KEY_LEN || salt.count != ver.ARGON2ID_SALT_LEN { throw NOXS_ERR.FORMAT }

    do {
        let result = try AEADChaCha20Poly1305.encrypt(
            plaintext.bytes,
            key: key.bytes,
            iv: salt.subdata(in: ver.ARGON2ID_SALT_LEN - ver.CHACHAPOLY_NONCE_LEN ..< ver.ARGON2ID_SALT_LEN).bytes,
            authenticationHeader: []
        )
        return Data([ver.VERSION_BYTE]) + salt + Data(result.cipherText) + Data(result.authenticationTag)
    } catch {
        throw NOXS_ERR.CORE_CIPHER
    }
}

public func encrypt(password: inout Data, plaintext: inout Data, ver: NOXS_VER) throws -> Data {
    var key = try deriveKey(password: &password, ver: ver)
    return try encrypt(key: &key.key, salt: &key.salt, plaintext: &plaintext, ver: ver)
}

public func decrypt(key: inout Data, ciphertext: inout Data) throws -> Data {
    if key.count != ARGON2ID_KEY_LEN { throw NOXS_ERR.FORMAT }

    do {
        let v = ciphertext[0]

        let ver = switch v {
        case NOXS_VER.ONE.VERSION_BYTE: NOXS_VER.ONE
        case NOXS_VER.X.VERSION_BYTE: NOXS_VER.X
        default: throw NOXS_ERR.CORE_CIPHER
        }

        let iv = ciphertext.subdata(in: VERSION_PREFIX_LEN + ver.ARGON2ID_SALT_LEN - ver.CHACHAPOLY_NONCE_LEN ..< VERSION_PREFIX_LEN + ver.ARGON2ID_SALT_LEN).bytes
        let tag = ciphertext.subdata(in: ciphertext.count - CHACHAPOLY_TAG_LEN ..< ciphertext.count).bytes

        let result = try ciphertext.withUnsafeMutableBytes { cipherBytes in
            try AEADChaCha20Poly1305.decrypt(
                Data(bytesNoCopy: cipherBytes.baseAddress! + VERSION_PREFIX_LEN + ver.ARGON2ID_SALT_LEN,
                     count: cipherBytes.count - VERSION_PREFIX_LEN - ver.ARGON2ID_SALT_LEN - CHACHAPOLY_TAG_LEN,
                     deallocator: .none).bytes,
                key: key.bytes,
                iv: iv,
                authenticationHeader: [],
                authenticationTag: tag
            )
        }

        if !result.success { throw NOXS_ERR.CORE_CIPHER }

        return Data(result.plainText)

    } catch {
        throw NOXS_ERR.CORE_CIPHER
    }
}

public func decrypt(password: inout Data, ciphertext: inout Data) throws -> Data {
    if ciphertext.count < 1 { throw NOXS_ERR.FORMAT }

    let v = ciphertext[0]

    let ver = switch v {
    case NOXS_VER.ONE.VERSION_BYTE: NOXS_VER.ONE
    case NOXS_VER.X.VERSION_BYTE: NOXS_VER.X
    default: throw NOXS_ERR.FORMAT
    }

    if ciphertext.count < VERSION_PREFIX_LEN + ver.ARGON2ID_SALT_LEN + CHACHAPOLY_TAG_LEN { throw NOXS_ERR.FORMAT }

    var salt = ciphertext.withUnsafeMutableBytes { cipherBytes in
        Data(bytesNoCopy: cipherBytes.baseAddress! + VERSION_PREFIX_LEN, count: ver.ARGON2ID_SALT_LEN, deallocator: .none)
    }
    // var salt = ciphertext.subdata(in: VERSION_PREFIX_LEN ..< VERSION_PREFIX_LEN + ver.ARGON2ID_SALT_LEN)

    var key = try deriveKey(password: &password, salt: &salt)

    return try decrypt(key: &key, ciphertext: &ciphertext)
}
