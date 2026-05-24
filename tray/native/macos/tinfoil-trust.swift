import Foundation
import Security

struct ExitError: Error {
    let code: Int32
    let message: String
}

func fail(_ code: Int32, _ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code)
}

func readCertificate(at path: String) -> SecCertificate {
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
        fail(2, "Could not read certificate at \(path)")
    }
    let der: Data
    if let pem = String(data: data, encoding: .utf8), pem.contains("-----BEGIN") {
        let body = pem
            .components(separatedBy: .newlines)
            .filter { !$0.hasPrefix("-----") }
            .joined()
        guard let decoded = Data(base64Encoded: body) else {
            fail(3, "Could not decode PEM body")
        }
        der = decoded
    } else {
        der = data
    }
    guard let cert = SecCertificateCreateWithData(nil, der as CFData) else {
        fail(4, "Invalid certificate data")
    }
    return cert
}

func install(_ cert: SecCertificate) {
    let policy = SecPolicyCreateSSL(true, nil)
    let settings: [[String: Any]] = [
        [
            kSecTrustSettingsResult as String: NSNumber(value: SecTrustSettingsResult.trustRoot.rawValue),
            kSecTrustSettingsPolicy as String: policy
        ]
    ]
    let status = SecTrustSettingsSetTrustSettings(cert, .user, settings as CFArray)
    if status != errSecSuccess {
        fail(Int32(status), "SecTrustSettingsSetTrustSettings failed: \(status)")
    }
}

func uninstall(_ cert: SecCertificate) {
    let status = SecTrustSettingsRemoveTrustSettings(cert, .user)
    if status != errSecSuccess && status != errSecItemNotFound {
        fail(Int32(status), "SecTrustSettingsRemoveTrustSettings failed: \(status)")
    }
}

func check(_ cert: SecCertificate) -> Bool {
    var settingsOut: CFArray?
    let status = SecTrustSettingsCopyTrustSettings(cert, .user, &settingsOut)
    return status == errSecSuccess
}

let args = CommandLine.arguments
guard args.count >= 3 else {
    fail(1, "Usage: tinfoil-trust <install|uninstall|check> <cert-path>")
}

let command = args[1]
let path = args[2]
let cert = readCertificate(at: path)

switch command {
case "install":
    install(cert)
case "uninstall":
    uninstall(cert)
case "check":
    exit(check(cert) ? 0 : 10)
default:
    fail(1, "Unknown command: \(command)")
}

exit(0)
