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
