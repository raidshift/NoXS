import Foundation

enum DATA_ERR: Error {
    case CORE_RND
    case FORMAT_BASE64
}

let DATA_ERR_TEXT_FORMAT_BASE64 = "Input data is not base64 encoded"
let DATA_ERR_CORE_RND = "Invoking random number generator failed"

extension DATA_ERR: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .CORE_RND:
            return NSLocalizedString(DATA_ERR_CORE_RND, comment: DATA_ERR_CORE_RND)
        case .FORMAT_BASE64:
            return NSLocalizedString(DATA_ERR_TEXT_FORMAT_BASE64, comment: DATA_ERR_TEXT_FORMAT_BASE64)
        }
    }
}

extension Data {
    var hexString: String {
        return map { byte in String(format: "%02x", byte) }.joined()
    }

    var filterBase64: Data {
        get throws {
            let str = String(decoding: self, as: UTF8.self)
            let lines = str.components(separatedBy: .newlines)
            var b64str = ""

            lines.forEach {
                let line = $0.trimmingCharacters(in: .whitespaces)
                if line != "", !line.hasPrefix("#") { b64str += line }
            }

            return try Data(base64Encoded: (b64str.filter { !$0.isWhitespace }).data(using: .utf8) ?? { throw DATA_ERR.FORMAT_BASE64 }()) ?? { throw DATA_ERR.FORMAT_BASE64 }()
        }
    }
}
