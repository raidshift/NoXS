import Foundation
@testable import NoXS
import XCTest

extension Data {
    var hexString: String {
        return map { byte in String(format: "%02x", byte) }.joined()
    }

    init?(hex: String) {
        guard hex.count.isMultiple(of: 2) else {
            return nil
        }

        let chars = hex.map { $0 }
        let bytes = stride(from: 0, to: chars.count, by: 2)
            .map { String(chars[$0]) + String(chars[$0 + 1]) }
            .compactMap { UInt8($0, radix: 16) }

        guard hex.count / bytes.count == 2 else { return nil }
        self.init(bytes)
    }
}

let passwordHex = "b102a3049c060f"
let keyHex = "ba49c1d86ab3b281e3cafe626e84274d6600504ec8bb072149b356ce1faea48b"
let plaintextHex = "6de01091d749f189c4e25aa315b314aa"
let nonceHex = "a71ea4bf40414e434bc54649"
let versionHex = "01"
let saltHex = "01020304" + nonceHex
let encryptedHex = "91352cd42cf496937b700a902c01d9d4"
let tagHex = "adcacd100c31dc5b2fa4c1f4575e684f"
let ciphertextHex = versionHex + saltHex + encryptedHex + tagHex

class XTests: XCTestCase {
    func testKeyDerivation() {
        var password = Data(hex: passwordHex)!
        var salt = Data(hex: saltHex)!

        do {
            let key = try deriveKey(password: &password, salt: &salt)
            XCTAssert(key.hexString == keyHex)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testEncrypt() {
        var password = Data(hex: passwordHex)!
        var key = Data(hex: keyHex)!
        var salt = Data(hex: saltHex)!
        var plaintext = Data(hex: plaintextHex)!

        do {
            let ciphertext = try encrypt(key: &key, salt: &salt, plaintext: &plaintext)
            XCTAssert(ciphertext.hexString == ciphertextHex)

        } catch {
            XCTFail(error.localizedDescription)
        }

        do {
            plaintext = Data()
            let ciphertext = try encrypt(password: &password, plaintext: &plaintext)
            XCTAssert(ciphertext.count == VERSION_PREFIX_LEN + ARGON2ID_SALT_LEN + plaintext.count + CHACHAPOLY_TAG_LEN)

        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testDecrypt() {
        var password = Data(hex: passwordHex)!
        var key = Data(hex: keyHex)!
        var ciphertext = Data(hex: ciphertextHex)!

        do {
            let plaintext = try decrypt(key: &key, ciphertext: &ciphertext)
            XCTAssert(plaintext.hexString == plaintextHex)

        } catch {
            XCTFail(error.localizedDescription)
        }

        do {
            let plaintext = try decrypt(password: &password, ciphertext: &ciphertext)
            XCTAssert(plaintext.hexString == plaintextHex)

        } catch {
            XCTFail(error.localizedDescription)
        }

        do {
            var ciphertext = Data(hex: versionHex + saltHex + tagHex + tagHex)!
            _ = try decrypt(password: &password, ciphertext: &ciphertext)
        } catch NOXS_ERR.CORE_CIPHER {}
        catch { XCTFail(error.localizedDescription) }

        do {
            var ciphertext = Data(hex: "ab" + saltHex + tagHex)!
            _ = try decrypt(password: &password, ciphertext: &ciphertext)
        } catch NOXS_ERR.FORMAT {}
        catch { XCTFail(error.localizedDescription) }

        do {
            var ciphertext = Data(hex: versionHex + nonceHex + tagHex)!
            _ = try decrypt(password: &password, ciphertext: &ciphertext)
        } catch NOXS_ERR.FORMAT {}
        catch { XCTFail(error.localizedDescription) }
    }
}
