import Foundation
import HXDataLock

enum CliFailure: Error, CustomStringConvertible {
    case message(String)
    var description: String {
        switch self {
        case .message(let text): return text
        }
    }
}

let args = Array(CommandLine.arguments.dropFirst())

func flag(_ name: String) -> String? {
    guard let index = args.firstIndex(of: name), index + 1 < args.count else { return nil }
    return args[index + 1]
}

func requireFlag(_ name: String) throws -> String {
    guard let value = flag(name) else { throw CliFailure.message("missing \(name)") }
    return value
}

func readObject(_ path: String) throws -> [String: Any] {
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    let parsed = try JSONSerialization.jsonObject(with: data)
    guard let object = parsed as? [String: Any] else {
        throw CliFailure.message("\(path) is not a JSON object")
    }
    return object
}

func writeObject(_ path: String, _ value: [String: Any]) throws {
    let data = try JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys])
    var text = String(decoding: data, as: UTF8.self)
    if !text.hasSuffix("\n") { text.append("\n") }
    try Data(text.utf8).write(to: URL(fileURLWithPath: path))
}

do {
    guard let command = args.first else {
        throw CliFailure.message("usage: hxdl-swift lock|open ...")
    }
    switch command {
    case "lock":
        let document = try readObject(try requireFlag("--public"))
        guard let write = document["publicWriteKey"] as? [String: Any] else {
            throw CliFailure.message("public document has no publicWriteKey")
        }
        if let expected = flag("--expect-key-id"), expected != (write["keyId"] as? String) {
            throw CliFailure.message("Public Key Document keyId does not match the expected keyId")
        }
        let plaintext = try Data(contentsOf: URL(fileURLWithPath: try requireFlag("--in")))
        let envelope = try HxDataLock.lockBytes(publicWriteKey: write, plaintext: plaintext)
        try writeObject(try requireFlag("--out"), envelope)
    case "rewrap":
        let keyring = try readObject(try requireFlag("--keyring"))
        let envName = flag("--password-env") ?? "HXDL_TEST_PASSWORD"
        let newName = try requireFlag("--new-password-env")
        guard let current = ProcessInfo.processInfo.environment[envName], !current.isEmpty else {
            throw CliFailure.message("environment variable \(envName) is empty")
        }
        guard let next = ProcessInfo.processInfo.environment[newName], !next.isEmpty else {
            throw CliFailure.message("environment variable \(newName) is empty")
        }
        let rewrapped = try HxDataLock.rewrapKeyring(
            keyring: keyring,
            currentPassword: current,
            newPassword: next,
            allowLowScryptN: args.contains("--allow-low-scrypt-n"),
            allowWeakPassword: args.contains("--allow-weak-password"),
            publicKeyring: args.contains("--public-keyring")
        )
        try writeObject(try requireFlag("--out"), rewrapped)
    case "stream-lock":
        let document = try readObject(try requireFlag("--public"))
        guard let write = document["publicWriteKey"] as? [String: Any] else {
            throw CliFailure.message("public document has no publicWriteKey")
        }
        if let expected = flag("--expect-key-id"), expected != (write["keyId"] as? String) {
            throw CliFailure.message("Public Key Document keyId does not match the expected keyId")
        }
        let spki = Data(base64Encoded: write["spki"] as? String ?? "") ?? Data()
        let plaintext = try Data(contentsOf: URL(fileURLWithPath: try requireFlag("--in")))
        let chunkSize = Int(flag("--chunk-size") ?? "64") ?? 64
        let sealed = try HxDataLock.lockStream(keyId: write["keyId"] as? String ?? "", recipientSpki: spki, plaintext: plaintext, chunkSize: chunkSize)
        try sealed.write(to: URL(fileURLWithPath: try requireFlag("--out")))
    case "stream-open":
        let keyring = try readObject(try requireFlag("--keyring"))
        let envName = flag("--password-env") ?? "HXDL_TEST_PASSWORD"
        guard let password = ProcessInfo.processInfo.environment[envName], !password.isEmpty else {
            throw CliFailure.message("environment variable \(envName) is empty")
        }
        let material = try HxDataLock.keyMaterial(keyring: keyring, masterPassword: password)
        let container = try Data(contentsOf: URL(fileURLWithPath: try requireFlag("--in")))
        let plain = try HxDataLock.openStream(keyId: material.keyId, rawPrivate: material.rawPrivate, recipientSpki: material.spki, container: container)
        try plain.write(to: URL(fileURLWithPath: try requireFlag("--out")))
    case "seal":
        let document = try readObject(try requireFlag("--public"))
        guard let write = document["publicWriteKey"] as? [String: Any] else {
            throw CliFailure.message("public document has no publicWriteKey")
        }
        let spki = Data(base64Encoded: write["spki"] as? String ?? "") ?? Data()
        let plaintext = try Data(contentsOf: URL(fileURLWithPath: try requireFlag("--in")))
        let chunkSize = Int(flag("--chunk-size") ?? "8") ?? 8
        let sealed = try HxDataLock.sealChunked(
            keyId: write["keyId"] as? String ?? "",
            recipientSpki: spki,
            plaintext: plaintext,
            chunkSize: chunkSize,
            fileId: try requireFlag("--file-id")
        )
        let directory = try requireFlag("--out-dir")
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        try writeObject(directory + "/manifest.json", sealed.manifest)
        for (index, chunk) in sealed.chunks.enumerated() {
            try chunk.write(to: URL(fileURLWithPath: directory + "/chunk-\(index).bin"))
        }
    case "open-manifest":
        let keyring = try readObject(try requireFlag("--keyring"))
        let envName = flag("--password-env") ?? "HXDL_TEST_PASSWORD"
        guard let password = ProcessInfo.processInfo.environment[envName], !password.isEmpty else {
            throw CliFailure.message("environment variable \(envName) is empty")
        }
        let material = try HxDataLock.keyMaterial(keyring: keyring, masterPassword: password)
        let manifest = try readObject(try requireFlag("--manifest"))
        let directory = try requireFlag("--chunk-dir")
        let count = (manifest["chunks"] as? [Any])?.count ?? 0
        let chunks = try (0..<count).map { index in
            try Data(contentsOf: URL(fileURLWithPath: directory + "/chunk-\(index).bin"))
        }
        let plain = try HxDataLock.openChunked(
            keyId: material.keyId,
            rawPrivate: material.rawPrivate,
            recipientSpki: material.spki,
            manifest: manifest,
            sealedChunks: chunks
        )
        try plain.write(to: URL(fileURLWithPath: try requireFlag("--out")))
    case "verify-attestation":
        let envelope = try Data(contentsOf: URL(fileURLWithPath: try requireFlag("--envelope")))
        let attestation = try readObject(try requireFlag("--attestation"))
        try HxDataLock.verifyEnvelope(attestation: attestation, envelopeJSON: envelope, expectedSignerKeyId: flag("--expect-signer"))
    case "open":
        let keyring = try readObject(try requireFlag("--keyring"))
        let envelope = try readObject(try requireFlag("--in"))
        let envName = flag("--password-env") ?? "HXDL_TEST_PASSWORD"
        guard let password = ProcessInfo.processInfo.environment[envName], !password.isEmpty else {
            throw CliFailure.message("environment variable \(envName) is empty")
        }
        let plaintext = try HxDataLock.openBytes(keyring: keyring, masterPassword: password, envelope: envelope)
        try plaintext.write(to: URL(fileURLWithPath: try requireFlag("--out")))
    default:
        throw CliFailure.message("unknown command \(command)")
    }
} catch {
    let line = "hxdl-swift: \(error)\n"
    try? FileHandle.standardError.write(contentsOf: Data(line.utf8))
    exit(1)
}
