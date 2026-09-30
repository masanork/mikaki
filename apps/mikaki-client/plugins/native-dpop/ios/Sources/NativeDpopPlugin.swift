import Foundation
import Security
import Tauri

private struct SignArgs: Decodable { let input: String }

class NativeDpopPlugin: Plugin {
    private let tag = "app.mikaki.vault.dpop.v1".data(using: .utf8)!

    private func key() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess, let existing = item { return existing as! SecKey }
        guard status == errSecItemNotFound else { throw NSError(domain: "NativeDpop", code: Int(status)) }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ]
        ]
        var error: Unmanaged<CFError>?
        guard let created = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw (error?.takeRetainedValue() as Error?) ?? NSError(domain: "NativeDpop", code: -1)
        }
        return created
    }

    @objc public func publicKey(_ invoke: Invoke) {
        do {
            guard let publicKey = SecKeyCopyPublicKey(try key()),
                  let raw = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
                  raw.count == 65, raw[0] == 4 else { throw NSError(domain: "NativeDpop", code: -2) }
            invoke.resolve([
                "x": Data(raw[1..<33]).base64URLEncodedString(),
                "y": Data(raw[33..<65]).base64URLEncodedString()
            ])
        } catch { invoke.reject("OS DPoP key unavailable") }
    }

    @objc public func sign(_ invoke: Invoke) {
        do {
            let input = try invoke.parseArgs(SignArgs.self).input
            guard input.utf8.count <= 4096, input.utf8.allSatisfy({ $0 < 128 }) else {
                throw NSError(domain: "NativeDpop", code: -3)
            }
            var error: Unmanaged<CFError>?
            guard let der = SecKeyCreateSignature(try key(), .ecdsaSignatureMessageX962SHA256,
                                                   Data(input.utf8) as CFData, &error) as Data? else {
                throw (error?.takeRetainedValue() as Error?) ?? NSError(domain: "NativeDpop", code: -4)
            }
            invoke.resolve(["der": der.base64URLEncodedString()])
        } catch { invoke.reject("OS DPoP signature unavailable") }
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}

@_cdecl("init_plugin_native_dpop")
func initPlugin() -> Plugin { NativeDpopPlugin() }
