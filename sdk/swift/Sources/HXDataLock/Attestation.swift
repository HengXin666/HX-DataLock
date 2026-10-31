import Crypto
import Foundation

enum Attestation {
    static let spkiPrefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
    static let pkcs8Prefix = Data([
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ])

    static func generate() -> (privateKey: Data, publicSpki: Data) {
        let key = Curve25519.Signing.PrivateKey()
        return (pkcs8Prefix + key.rawRepresentation, spkiPrefix + key.publicKey.rawRepresentation)
    }

    static func keyId(_ publicSpki: Data) -> String {
        "ed25519:" + String(Codec.sha256Base64Url(publicSpki).prefix(22))
    }

    static func signEnvelope(privatePkcs8: Data, envelopeJSON: Data, recipientKeyId: String, context: String = "") throws -> [String: Any] {
        if context.contains("\n") || recipientKeyId.contains("\n") {
            throw DataLockError.code("INVALID_ARGUMENT", "attestation fields must not contain newlines")
        }
        let digest = Codec.sha256Base64Url(envelopeJSON)
        let message = Data("hxdl.attestation.v1\n\(digest)\n\(recipientKeyId)\n\(context)\n".utf8)
        let raw = try rawPrivate(privatePkcs8)
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: raw)
        let signature = try key.signature(for: message)
        let publicSpki = spkiPrefix + key.publicKey.rawRepresentation
        return [
            "schema": "hxdl.attestation.v1",
            "createdAt": isoNow(),
            "envelopeSha256": digest,
            "context": context,
            "recipientKeyId": recipientKeyId,
            "signer": [
                "alg": "Ed25519",
                "keyId": keyId(publicSpki),
                "publicKey": publicSpki.base64EncodedString(),
            ],
            "signature": signature.base64EncodedString(),
        ]
    }

    static func verifyEnvelope(attestation: [String: Any], envelopeJSON: Data, expectedSignerKeyId: String? = nil) throws {
        guard attestation["schema"] as? String == "hxdl.attestation.v1" else {
            throw DataLockError.code("INVALID_ATTESTATION", "attestation schema")
        }
        let digest = Codec.sha256Base64Url(envelopeJSON)
        guard attestation["envelopeSha256"] as? String == digest else {
            throw DataLockError.code("INVALID_ATTESTATION", "attestation does not match this Data Envelope")
        }
        let recipient = attestation["recipientKeyId"] as? String ?? ""
        let context = attestation["context"] as? String ?? ""
        let message = Data("hxdl.attestation.v1\n\(digest)\n\(recipient)\n\(context)\n".utf8)
        try verify(attestation: attestation, message: message, expectedSignerKeyId: expectedSignerKeyId)
    }

    static func signedManifestBytes(issuer: String, payload: Any) -> Data {
        let text = StableJSON.indent(["issuer": issuer, "payload": payload], indent: 0) + "\n"
        return Data(text.utf8)
    }

    static func signManifest(privatePkcs8: Data, issuer: String, payload: [String: Any]) throws -> [String: Any] {
        let raw = try rawPrivate(privatePkcs8)
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: raw)
        let signature = try key.signature(for: signedManifestBytes(issuer: issuer, payload: payload))
        let publicSpki = spkiPrefix + key.publicKey.rawRepresentation
        return [
            "schema": "hxdl.signedManifest.v2",
            "signedAt": isoNow(),
            "issuer": issuer,
            "signer": [
                "alg": "Ed25519",
                "keyId": keyId(publicSpki),
                "publicKey": publicSpki.base64EncodedString(),
            ],
            "payload": payload,
            "signature": signature.base64EncodedString(),
        ]
    }

    static func verifyManifest(_ document: [String: Any], expectedSignerKeyId: String? = nil) throws {
        guard document["schema"] as? String == "hxdl.signedManifest.v2" else {
            throw DataLockError.code("INVALID_ATTESTATION", "signed manifest schema")
        }
        let issuer = document["issuer"] as? String ?? ""
        let payload = document["payload"] ?? [:]
        try verify(
            attestation: document,
            message: signedManifestBytes(issuer: issuer, payload: payload),
            expectedSignerKeyId: expectedSignerKeyId
        )
    }

    private static func verify(attestation: [String: Any], message: Data, expectedSignerKeyId: String?) throws {
        guard let signer = attestation["signer"] as? [String: Any], signer["alg"] as? String == "Ed25519" else {
            throw DataLockError.code("UNSUPPORTED_ALGORITHM", "signer must use Ed25519")
        }
        let publicSpki = Data(base64Encoded: signer["publicKey"] as? String ?? "") ?? Data()
        let id = keyId(publicSpki)
        guard signer["keyId"] as? String == id else {
            throw DataLockError.code("INVALID_ATTESTATION", "signer keyId does not match the public key")
        }
        if let expectedSignerKeyId, expectedSignerKeyId != id {
            throw DataLockError.code("INVALID_ATTESTATION", "attestation signer is not the expected key")
        }
        let rawPublic = try rawPublic(publicSpki)
        let signature = Data(base64Encoded: attestation["signature"] as? String ?? "") ?? Data()
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: rawPublic)
        guard publicKey.isValidSignature(signature, for: message) else {
            throw DataLockError.code("INVALID_ATTESTATION", "signature is invalid")
        }
    }

    private static func rawPrivate(_ pkcs8: Data) throws -> Data {
        guard pkcs8.starts(with: pkcs8Prefix), pkcs8.count == pkcs8Prefix.count + 32 else {
            throw DataLockError.code("INVALID_ARGUMENT", "attestation private key is not Ed25519")
        }
        return pkcs8.suffix(32)
    }

    private static func rawPublic(_ spki: Data) throws -> Data {
        guard spki.starts(with: spkiPrefix), spki.count == spkiPrefix.count + 32 else {
            throw DataLockError.code("INVALID_ATTESTATION", "attestation public key is not Ed25519")
        }
        return spki.suffix(32)
    }
}

enum StableJSON {
    static func indent(_ value: Any, indent: Int) -> String {
        let pad = String(repeating: " ", count: indent)
        let inner = String(repeating: " ", count: indent + 2)
        if let rows = value as? [Any] {
            if rows.isEmpty { return "[]" }
            let lines = rows.map { "\(inner)\(self.indent($0, indent: indent + 2))" }
            return "[\n" + lines.joined(separator: ",\n") + "\n\(pad)]"
        }
        if let object = value as? [String: Any] {
            if object.isEmpty { return "{}" }
            let lines = object.keys.sorted().map { key in
                "\(inner)\(quote(key)): \(self.indent(object[key]!, indent: indent + 2))"
            }
            return "{\n" + lines.joined(separator: ",\n") + "\n\(pad)}"
        }
        if let text = value as? String { return quote(text) }
        if let flag = value as? Bool { return flag ? "true" : "false" }
        if let number = value as? Int { return String(number) }
        if let number = value as? NSNumber { return String(number.intValue) }
        if value is NSNull { return "null" }
        return "null"
    }

    static func quote(_ value: String) -> String {
        var out = "\""
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x5c: out += "\\\\"
            case 0x22: out += "\\\""
            case 0x0a: out += "\\n"
            case 0x0d: out += "\\r"
            case 0x09: out += "\\t"
            case 0..<0x20: out += String(format: "\\u%04x", scalar.value)
            default: out.unicodeScalars.append(scalar)
            }
        }
        out += "\""
        return out
    }
}
