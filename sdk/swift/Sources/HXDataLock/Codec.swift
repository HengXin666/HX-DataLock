import Crypto
import _CryptoExtras
import Foundation

public enum DataLockError: Error, Equatable {
    case code(String, String)
}

public struct PasswordStrengthReport: Sendable {
    public var level: String
    public var allowed: Bool
    public var estimatedEntropyBits: Double
}

enum Codec {
    static let x25519SpkiPrefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00])
    static let x25519Pkcs8Prefix = Data([
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
    ])
    static let envelopeAlg: [String: String] = ["aead": "AES-256-GCM", "kdf": "HKDF-SHA256", "kem": "X25519"]

    static func spki(rawPublic: Data) -> Data { x25519SpkiPrefix + rawPublic }
    static func rawPublic(spki: Data) throws -> Data {
        guard spki.starts(with: x25519SpkiPrefix), spki.count == x25519SpkiPrefix.count + 32 else {
            throw DataLockError.code("INVALID_KEYRING", "public Write Key SPKI is not X25519")
        }
        return spki.suffix(32)
    }

    static func pkcs8(rawPrivate: Data) -> Data { x25519Pkcs8Prefix + rawPrivate }
    static func rawPrivate(pkcs8: Data) throws -> Data {
        guard pkcs8.starts(with: x25519Pkcs8Prefix), pkcs8.count == x25519Pkcs8Prefix.count + 32 else {
            throw DataLockError.code("INVALID_KEYRING", "Read Key PKCS8 is not X25519")
        }
        return pkcs8.suffix(32)
    }

    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    static func sha256Base64Url(_ data: Data) -> String {
        sha256(data).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func scrypt(password: String, salt: Data, n: Int, r: Int, p: Int) throws -> Data {
        let normalized = password.precomposedStringWithCanonicalMapping
        let key = try KDF.Scrypt.deriveKey(
            from: Array(normalized.utf8),
            salt: Array(salt),
            outputByteCount: 32,
            rounds: n,
            blockSize: r,
            parallelism: p
        )
        return key.withUnsafeBytes { Data($0) }
    }

    static func aesSeal(key: Data, plaintext: Data, aad: Data) throws -> (nonce: Data, ciphertext: Data, tag: Data) {
        let nonce = AES.GCM.Nonce()
        let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: nonce, authenticating: aad)
        return (Data(nonce), box.ciphertext, box.tag)
    }

    static func aesOpen(key: Data, nonce: Data, ciphertext: Data, tag: Data, aad: Data) throws -> Data {
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
    }

    static func hkdf(secret: Data, salt: Data, info: Data) -> Data {
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: secret),
            salt: salt,
            info: info,
            outputByteCount: 32
        )
        return key.withUnsafeBytes { Data($0) }
    }

    static func sharedSecret(rawPrivate: Data, rawPublic: Data) throws -> Data {
        let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawPrivate)
        let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: rawPublic)
        let shared = try priv.sharedSecretFromKeyAgreement(with: pub)
        return shared.withUnsafeBytes { Data($0) }
    }
}

public enum HxDataLock {
    public static func createKeyring(masterPassword: String, scryptN: Int = 262144, allowLowScryptN: Bool = false) throws -> [String: Any] {
        if scryptN < 131072 && !allowLowScryptN {
            throw DataLockError.code("INSECURE_SCRYPT_PARAMETERS", "scrypt N is below 2^17")
        }
        let priv = Curve25519.KeyAgreement.PrivateKey()
        let publicDer = Codec.spki(rawPublic: priv.publicKey.rawRepresentation)
        let privateDer = Codec.pkcs8(rawPrivate: priv.rawRepresentation)
        let keyId = "x25519:" + String(Codec.sha256Base64Url(publicDer).prefix(22))
        let salt = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let wrapping = try Codec.scrypt(password: masterPassword, salt: salt, n: scryptN, r: 8, p: 1)
        let aad = Data("hxdl.keyring.v1:\(keyId):scrypt:AES-256-GCM".utf8)
        let sealed = try Codec.aesSeal(key: wrapping, plaintext: privateDer, aad: aad)
        return [
            "schema": "hxdl.keyring.v1",
            "createdAt": isoNow(),
            "publicWriteKey": [
                "alg": "X25519",
                "keyId": keyId,
                "spki": publicDer.base64EncodedString(),
            ],
            "encryptedReadKey": [
                "kdf": [
                    "name": "scrypt",
                    "salt": salt.base64EncodedString(),
                    "N": scryptN,
                    "r": 8,
                    "p": 1,
                    "keyLength": 32,
                ],
                "aead": [
                    "name": "AES-256-GCM",
                    "nonce": sealed.nonce.base64EncodedString(),
                    "tag": sealed.tag.base64EncodedString(),
                ],
                "ciphertext": sealed.ciphertext.base64EncodedString(),
            ],
        ]
    }

    public static func lockBytes(publicWriteKey: [String: Any], plaintext: Data) throws -> [String: Any] {
        let keyId = publicWriteKey["keyId"] as? String ?? ""
        let spki = Data(base64Encoded: publicWriteKey["spki"] as? String ?? "") ?? Data()
        let rawPublic = try Codec.rawPublic(spki: spki)
        let eph = Curve25519.KeyAgreement.PrivateKey()
        let shared = try Codec.sharedSecret(rawPrivate: eph.rawRepresentation, rawPublic: rawPublic)
        let salt = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let info = Data("hxdl.envelope.v1:\(keyId)".utf8)
        let content = Codec.hkdf(secret: shared, salt: salt, info: info)
        let aad = Data("hxdl.envelope.v1:\(keyId):X25519:HKDF-SHA256:AES-256-GCM".utf8)
        let sealed = try Codec.aesSeal(key: content, plaintext: plaintext, aad: aad)
        return [
            "schema": "hxdl.envelope.v1",
            "createdAt": isoNow(),
            "recipientKeyId": keyId,
            "alg": ["kem": "X25519", "kdf": "HKDF-SHA256", "aead": "AES-256-GCM"],
            "ephemeralPublicKey": Codec.spki(rawPublic: eph.publicKey.rawRepresentation).base64EncodedString(),
            "hkdfSalt": salt.base64EncodedString(),
            "nonce": sealed.nonce.base64EncodedString(),
            "tag": sealed.tag.base64EncodedString(),
            "ciphertext": sealed.ciphertext.base64EncodedString(),
        ]
    }

    public static func openBytes(keyring: [String: Any], masterPassword: String, envelope: [String: Any]) throws -> Data {
        guard envelope["schema"] as? String == "hxdl.envelope.v1" else {
            throw DataLockError.code("UNSUPPORTED_SCHEMA", "envelope schema")
        }
        let keyId = (keyring["publicWriteKey"] as? [String: Any])?["keyId"] as? String ?? ""
        guard envelope["recipientKeyId"] as? String == keyId else {
            throw DataLockError.code("ENVELOPE_RECIPIENT_MISMATCH", "recipient")
        }
        let encrypted = keyring["encryptedReadKey"] as? [String: Any] ?? [:]
        let kdf = encrypted["kdf"] as? [String: Any] ?? [:]
        let aead = encrypted["aead"] as? [String: Any] ?? [:]
        let salt = Data(base64Encoded: kdf["salt"] as? String ?? "") ?? Data()
        let n = kdf["N"] as? Int ?? 0
        let wrapping = try Codec.scrypt(password: masterPassword, salt: salt, n: n, r: 8, p: 1)
        let wrapAad = Data("hxdl.keyring.v1:\(keyId):scrypt:AES-256-GCM".utf8)
        let privateDer = try Codec.aesOpen(
            key: wrapping,
            nonce: Data(base64Encoded: aead["nonce"] as? String ?? "") ?? Data(),
            ciphertext: Data(base64Encoded: encrypted["ciphertext"] as? String ?? "") ?? Data(),
            tag: Data(base64Encoded: aead["tag"] as? String ?? "") ?? Data(),
            aad: wrapAad
        )
        let rawPrivate = try Codec.rawPrivate(pkcs8: privateDer)
        let eph = try Codec.rawPublic(spki: Data(base64Encoded: envelope["ephemeralPublicKey"] as? String ?? "") ?? Data())
        let shared = try Codec.sharedSecret(rawPrivate: rawPrivate, rawPublic: eph)
        let info = Data("hxdl.envelope.v1:\(keyId)".utf8)
        let hkdfSalt = Data(base64Encoded: envelope["hkdfSalt"] as? String ?? "") ?? Data()
        let content = Codec.hkdf(secret: shared, salt: hkdfSalt, info: info)
        let openAad = Data("hxdl.envelope.v1:\(keyId):X25519:HKDF-SHA256:AES-256-GCM".utf8)
        return try Codec.aesOpen(
            key: content,
            nonce: Data(base64Encoded: envelope["nonce"] as? String ?? "") ?? Data(),
            ciphertext: Data(base64Encoded: envelope["ciphertext"] as? String ?? "") ?? Data(),
            tag: Data(base64Encoded: envelope["tag"] as? String ?? "") ?? Data(),
            aad: openAad
        )
    }
}

private func isoNow() -> String {
    let millis = Int((Date().timeIntervalSince1970 * 1000).rounded())
    let seconds = millis / 1000
    let fraction = millis % 1000
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    let stamp = formatter.string(from: Date(timeIntervalSince1970: TimeInterval(seconds)))
    let head = stamp.hasSuffix("Z") ? String(stamp.dropLast()) : stamp
    return String(format: "%@.%03dZ", head, fraction)
}
