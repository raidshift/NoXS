import Foundation
import NoXS

let COMMANDS = ["ea", "e", "da", "d"]

let BUILD = "2.S"
let VER = "V1.\(BUILD)\(String(repeating: " ", count: 3 - "\(BUILD)".count))"

let STD_ERR_INFO = """

NoXS \(VER) (https://github.com/raidshift/noxs)

Usage:
   noxs <cmd> <in_file> <out_file>
                     or
   noxs <cmd> <in_file> <out_file> <passw_file>

Commands:
   e = encrypt  |  ea = encrypt & base64-encode
   d = decrypt  |  da = base64-decode & decrypt

"""
let STD_ERR_PASSWORD_NO_MATCH = "Passwords do not match"
let STD_ERR_EQUAL_OUT_IN = "<out_file> must not be <in_file>"
let STD_ERR_EQUAL_PASSWD_OUT = "<passwd_file> must not be <out_file>"

let STD_OUT_ENTER_PASSWORD = "Enter password:"
let STD_OUT_CONFIRM_PASSWORD = "Confirm password:"

enum DATA_ERR: Error {
    case FORMAT_BASE64
}

let DATA_ERR_TEXT_FORMAT_BASE64 = "Input data is not base64 encoded"

extension DATA_ERR: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .FORMAT_BASE64:
            return NSLocalizedString(DATA_ERR_TEXT_FORMAT_BASE64, comment: DATA_ERR_TEXT_FORMAT_BASE64)
        }
    }
}

func exitWithError(_ out: String) {
    (out + "\n").data(using: .utf8).map(FileHandle.standardError.write); exit(1)
}

if CommandLine.arguments.count < 4
    || CommandLine.arguments.count > 5
    || !COMMANDS.contains(CommandLine.arguments[1])
{ exitWithError(STD_ERR_INFO) }

let inURL: URL = URL(fileURLWithPath: CommandLine.arguments[2])
let outURL = URL(fileURLWithPath: CommandLine.arguments[3])

if outURL.absoluteString == inURL.absoluteString { exitWithError(STD_ERR_EQUAL_OUT_IN) }

do {
    var password = Data()
    var passwordFromFile = false

    if CommandLine.arguments.count == 5 {
        let passwdURL = URL(fileURLWithPath: CommandLine.arguments[4])
        if passwdURL.absoluteString == outURL.absoluteString { exitWithError(STD_ERR_EQUAL_PASSWD_OUT) }
        password = try Data(contentsOf: passwdURL)
        passwordFromFile = true
    }

    var data = try Data(contentsOf: inURL)
    var isBase64data = false

    switch CommandLine.arguments[1] {
    case COMMANDS[0]:
        isBase64data = true
        fallthrough

    case COMMANDS[1]:
        var confirmPassword = Data()
        if !passwordFromFile {
            password = (String(validatingUTF8: UnsafePointer<CChar>(getpass(STD_OUT_ENTER_PASSWORD))) ?? "").data(using: .utf8)!
            confirmPassword = (String(validatingUTF8: UnsafePointer<CChar>(getpass(STD_OUT_CONFIRM_PASSWORD))) ?? "").data(using: .utf8)!
            if password != confirmPassword { exitWithError(STD_ERR_PASSWORD_NO_MATCH) }
        }
        if isBase64data {
            try encrypt(password: &password, plaintext: &data,ver: .ONE).base64EncodedData().write(to: outURL)
        } else {
            try encrypt(password: &password, plaintext: &data,ver: .ONE).write(to: outURL)
        }

    case COMMANDS[2]:
        isBase64data = true
        fallthrough

    case COMMANDS[3]:
        if !passwordFromFile {
            password = (String(validatingUTF8: UnsafePointer<CChar>(getpass(STD_OUT_ENTER_PASSWORD))) ?? "").data(using: .utf8)!
        }
        if isBase64data { data = try Data(base64Encoded: data) ?? { throw DATA_ERR.FORMAT_BASE64 }() }
        try decrypt(password: &password, ciphertext: &data).write(to: outURL)

    default:
        exitWithError(STD_ERR_PASSWORD_NO_MATCH)
    }

} catch {
    exitWithError(error.localizedDescription)
}
