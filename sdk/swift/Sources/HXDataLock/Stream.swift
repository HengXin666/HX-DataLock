import Crypto
import Foundation

enum StreamCodec {
    static func lock(keyId: String, recipientSpki: Data, plaintext: Data, chunkSize: Int, fileId: String? = nil, chunkIndex: Int? = nil) throws -> Data {
        let size = try requireChunkSize(chunkSize)
        if let fileId, fileId.isEmpty || fileId.contains("\n") {
            throw DataLockError.code("INVALID_ARGUMENT", "fileId must be a single-line string")
        }
        if let chunkIndex, chunkIndex < 0 {
            throw DataLockError.code("INVALID_ARGUMENT", "chunkIndex must be a non-negative integer")
        }
        let rawPublic = try Codec.rawPublic(spki: recipientSpki)
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralSpki = Codec.spki(rawPublic: ephemeral.publicKey.rawRepresentation)
        let shared = try Codec.sharedSecret(rawPrivate: ephemeral.rawRepresentation, rawPublic: rawPublic)
        let salt = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let info = Data("hxdl.stream.v1:\(keyId):".utf8) + Codec.sha256(recipientSpki)
        let key = Codec.hkdf(secret: shared, salt: salt, info: info)
        let header = headerJSON(
            keyId: keyId,
            ephemeral: ephemeralSpki.base64EncodedString(),
            salt: salt.base64EncodedString(),
            chunkSize: size,
            fileId: fileId,
            chunkIndex: chunkIndex
        )
        let headerSha = Codec.sha256Base64Url(header)
        var out = Data("HXDL".utf8)
        out.append(1)
        out.append(uint32(header.count))
        out.append(header)
        var offset = 0
        var index = 0
        if plaintext.isEmpty {
            try writeChunk(&out, key: key, keyId: keyId, chunkSize: size, index: 0, isLast: true, headerSha: headerSha, plaintext: Data())
            return out
        }
        while offset < plaintext.count {
            let end = min(offset + size, plaintext.count)
            let block = plaintext.subdata(in: offset..<end)
            let isLast = end == plaintext.count
            try writeChunk(&out, key: key, keyId: keyId, chunkSize: size, index: index, isLast: isLast, headerSha: headerSha, plaintext: block)
            offset = end
            index += 1
        }
        return out
    }

    static func open(keyId: String, rawPrivate: Data, recipientSpki: Data, container: Data) throws -> Data {
        var cursor = 0
        func take(_ n: Int, _ what: String) throws -> Data {
            guard cursor + n <= container.count else {
                throw DataLockError.code("TAMPERED_STREAM", "stream ended inside \(what)")
            }
            let slice = container.subdata(in: cursor..<(cursor + n))
            cursor += n
            return slice
        }
        let magic = try take(4, "stream magic")
        guard magic == Data("HXDL".utf8) else { throw DataLockError.code("TAMPERED_STREAM", "stream magic") }
        guard try take(1, "stream version").first == 1 else { throw DataLockError.code("UNSUPPORTED_SCHEMA", "stream version") }
        let headerLen = int32(try take(4, "stream header length"))
        guard headerLen > 0, headerLen <= 64 * 1024 else { throw DataLockError.code("TAMPERED_STREAM", "stream header length") }
        let headerBytes = try take(headerLen, "stream header")
        let header = try JSONSerialization.jsonObject(with: headerBytes) as? [String: Any] ?? [:]
        guard header["schema"] as? String == "hxdl.stream.v1" else { throw DataLockError.code("UNSUPPORTED_SCHEMA", "stream schema") }
        guard header["recipientKeyId"] as? String == keyId else { throw DataLockError.code("ENVELOPE_RECIPIENT_MISMATCH", "stream recipient") }
        let chunkSize = try requireChunkSize(Codec.jsonInt(header["chunkSize"]))
        let eph = try Codec.rawPublic(spki: Data(base64Encoded: header["ephemeralPublicKey"] as? String ?? "") ?? Data())
        let salt = Data(base64Encoded: header["hkdfSalt"] as? String ?? "") ?? Data()
        let shared = try Codec.sharedSecret(rawPrivate: rawPrivate, rawPublic: eph)
        let info = Data("hxdl.stream.v1:\(keyId):".utf8) + Codec.sha256(recipientSpki)
        let key = Codec.hkdf(secret: shared, salt: salt, info: info)
        let headerSha = Codec.sha256Base64Url(headerBytes)
        var plain = Data()
        var index = 0
        var sawLast = false
        while cursor < container.count {
            if sawLast { throw DataLockError.code("TAMPERED_STREAM", "stream continues after the last chunk") }
            let flag = try take(1, "chunk flag").first ?? 255
            guard flag == 0 || flag == 1 else { throw DataLockError.code("TAMPERED_STREAM", "stream chunk flag") }
            let isLast = flag == 1
            let bodyLen = int32(try take(4, "chunk length"))
            guard bodyLen >= 16, bodyLen <= chunkSize + 16 else { throw DataLockError.code("TAMPERED_STREAM", "stream chunk length") }
            let body = try take(bodyLen, "chunk body")
            let opened: Data
            do {
                opened = try openChunk(key: key, nonce: nonce(index, isLast), body: body, aad: aad(keyId, chunkSize, index, isLast, headerSha))
            } catch {
                throw DataLockError.code("TAMPERED_STREAM", "stream chunk authentication failed")
            }
            if !isLast && opened.count != chunkSize { throw DataLockError.code("TAMPERED_STREAM", "non-final stream chunk has an unexpected length") }
            plain.append(opened)
            index += 1
            sawLast = isLast
        }
        if !sawLast { throw DataLockError.code("TAMPERED_STREAM", "stream ended before the last chunk") }
        return plain
    }

    static func sealChunked(
        keyId: String,
        recipientSpki: Data,
        plaintext: Data,
        chunkSize: Int,
        fileId: String,
        version: Int = 1,
        previousManifest: [String: Any]? = nil,
        previousSealed: [Data]? = nil
    ) throws -> (manifest: [String: Any], chunks: [Data]) {
        let size = try requireChunkSize(chunkSize)
        if fileId.isEmpty { throw DataLockError.code("INVALID_ARGUMENT", "fileId is required") }
        if version < 1 { throw DataLockError.code("INVALID_ARGUMENT", "manifest version must be a positive integer") }
        if (previousManifest == nil) != (previousSealed == nil) {
            throw DataLockError.code("INVALID_ARGUMENT", "previousManifest and previousSealed must be passed together")
        }
        var previousByIndex: [Int: (hash: String, length: Int, sealed: Data)] = [:]
        if let previousManifest, let previousSealed {
            let entries = try manifestChunks(previousManifest)
            if previousManifest["fileId"] as? String != fileId {
                throw DataLockError.code("INVALID_MANIFEST", "previous manifest belongs to a different file")
            }
            if entries.count != previousSealed.count {
                throw DataLockError.code("INVALID_MANIFEST", "previous sealed chunk count does not match the manifest")
            }
            for (entry, sealed) in zip(entries, previousSealed) {
                if Codec.sha256Base64Url(sealed) != entry.sealedHash {
                    throw DataLockError.code("INVALID_MANIFEST", "previous sealed hash does not match the manifest")
                }
                previousByIndex[entry.index] = (entry.plainHash, entry.length, sealed)
            }
        }
        var chunks: [Data] = []
        var rows: [[String: Any]] = []
        var offset = 0
        var index = 0
        let blocks = split(plaintext, size)
        for (block, isLast) in blocks {
            _ = isLast
            let digest = Codec.sha256Base64Url(block)
            let reused = previousByIndex[index]
            let sealed: Data
            if let reused, reused.hash == digest, reused.length == block.count {
                sealed = reused.sealed
            } else {
                sealed = try lock(keyId: keyId, recipientSpki: recipientSpki, plaintext: block, chunkSize: size, fileId: fileId, chunkIndex: index)
            }
            rows.append([
                "index": index,
                "plaintextLength": block.count,
                "plaintextSha256": digest,
                "sealedSha256": Codec.sha256Base64Url(sealed),
            ])
            chunks.append(sealed)
            offset += block.count
            index += 1
        }
        let manifest: [String: Any] = [
            "schema": "hxdl.manifest.v1",
            "fileId": fileId,
            "version": version,
            "chunkSize": size,
            "totalPlaintextLength": offset,
            "chunks": rows,
        ]
        return (manifest, chunks)
    }

    static func openChunked(keyId: String, rawPrivate: Data, recipientSpki: Data, manifest: [String: Any], sealedChunks: [Data]) throws -> Data {
        let entries = try manifestChunks(manifest)
        if entries.count != sealedChunks.count {
            throw DataLockError.code("INVALID_MANIFEST", "sealed chunk count does not match the manifest")
        }
        var plain = Data()
        for (entry, sealed) in zip(entries, sealedChunks) {
            if Codec.sha256Base64Url(sealed) != entry.sealedHash {
                throw DataLockError.code("INVALID_MANIFEST", "sealed hash mismatch")
            }
            let opened = try open(keyId: keyId, rawPrivate: rawPrivate, recipientSpki: recipientSpki, container: sealed)
            if opened.count != entry.length || Codec.sha256Base64Url(opened) != entry.plainHash {
                throw DataLockError.code("TAMPERED_STREAM", "plaintext hash mismatch")
            }
            plain.append(opened)
        }
        if Codec.jsonInt(manifest["totalPlaintextLength"]) != plain.count {
            throw DataLockError.code("INVALID_MANIFEST", "manifest total length does not match the chunks")
        }
        return plain
    }

    private struct ChunkRow {
        var index: Int
        var length: Int
        var plainHash: String
        var sealedHash: String
    }

    private static func manifestChunks(_ manifest: [String: Any]) throws -> [ChunkRow] {
        guard manifest["schema"] as? String == "hxdl.manifest.v1" else {
            throw DataLockError.code("INVALID_MANIFEST", "manifest schema must be hxdl.manifest.v1")
        }
        guard let rows = manifest["chunks"] as? [[String: Any]], !rows.isEmpty else {
            throw DataLockError.code("INVALID_MANIFEST", "manifest must list at least one chunk")
        }
        return try rows.enumerated().map { expected, row in
            let index = Codec.jsonInt(row["index"])
            if index != expected { throw DataLockError.code("INVALID_MANIFEST", "manifest chunk indexes must be contiguous from 0") }
            guard let plain = row["plaintextSha256"] as? String, !plain.isEmpty,
                  let sealed = row["sealedSha256"] as? String, !sealed.isEmpty else {
                throw DataLockError.code("INVALID_MANIFEST", "manifest chunk is missing a hash")
            }
            return ChunkRow(index: index, length: Codec.jsonInt(row["plaintextLength"]), plainHash: plain, sealedHash: sealed)
        }
    }

    private static func split(_ plaintext: Data, _ size: Int) -> [(Data, Bool)] {
        if plaintext.isEmpty { return [(Data(), true)] }
        var blocks: [(Data, Bool)] = []
        var offset = 0
        while offset < plaintext.count {
            let end = min(offset + size, plaintext.count)
            blocks.append((plaintext.subdata(in: offset..<end), end == plaintext.count))
            offset = end
        }
        return blocks
    }

    private static func requireChunkSize(_ chunkSize: Int) throws -> Int {
        guard chunkSize >= 1, chunkSize <= 8 * 1024 * 1024 else {
            throw DataLockError.code("INVALID_ARGUMENT", "chunkSize must be an integer from 1 to 8388608")
        }
        return chunkSize
    }

    private static func headerJSON(keyId: String, ephemeral: String, salt: String, chunkSize: Int, fileId: String?, chunkIndex: Int?) -> Data {
        var text = "{\"schema\":\"hxdl.stream.v1\",\"recipientKeyId\":\(quote(keyId)),\"alg\":{\"kem\":\"X25519\",\"kdf\":\"HKDF-SHA256\",\"aead\":\"AES-256-GCM\"},\"ephemeralPublicKey\":\(quote(ephemeral)),\"hkdfSalt\":\(quote(salt)),\"chunkSize\":\(chunkSize)"
        if let fileId { text += ",\"fileId\":\(quote(fileId))" }
        if let chunkIndex { text += ",\"chunkIndex\":\(chunkIndex)" }
        text += "}"
        return Data(text.utf8)
    }

    private static func quote(_ value: String) -> String {
        var out = "\""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\\": out += "\\\\"
            case "\"": out += "\\\""
            default: out.unicodeScalars.append(scalar)
            }
        }
        out += "\""
        return out
    }

    private static func nonce(_ index: Int, _ isLast: Bool) -> Data {
        var data = Data(count: 12)
        var value = UInt64(index).bigEndian
        withUnsafeBytes(of: &value) { data.replaceSubrange(0..<8, with: $0) }
        data[11] = isLast ? 1 : 0
        return data
    }

    private static func aad(_ keyId: String, _ chunkSize: Int, _ index: Int, _ isLast: Bool, _ headerSha: String) -> Data {
        Data("hxdl.stream.v1:\(keyId):X25519:HKDF-SHA256:AES-256-GCM:\(chunkSize):\(index):\(isLast ? 1 : 0):\(headerSha)".utf8)
    }

    private static func writeChunk(_ out: inout Data, key: Data, keyId: String, chunkSize: Int, index: Int, isLast: Bool, headerSha: String, plaintext: Data) throws {
        let body = try Codec.aesSeal(key: key, nonce: nonce(index, isLast), plaintext: plaintext, aad: aad(keyId, chunkSize, index, isLast, headerSha))
        out.append(isLast ? 1 : 0)
        out.append(uint32(body.count))
        out.append(body)
    }

    private static func openChunk(key: Data, nonce: Data, body: Data, aad: Data) throws -> Data {
        guard body.count >= 16 else { throw DataLockError.code("TAMPERED_STREAM", "chunk") }
        let tag = body.suffix(16)
        let ciphertext = body.prefix(body.count - 16)
        return try Codec.aesOpen(key: key, nonce: nonce, ciphertext: Data(ciphertext), tag: Data(tag), aad: aad)
    }

    private static func uint32(_ value: Int) -> Data {
        var be = UInt32(value).bigEndian
        return Data(bytes: &be, count: 4)
    }

    private static func int32(_ data: Data) -> Int {
        data.reduce(0) { ($0 << 8) | Int($1) }
    }
}
