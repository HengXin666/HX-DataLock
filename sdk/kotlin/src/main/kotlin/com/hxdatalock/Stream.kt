package com.hxdatalock

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest

internal object Stream {
    private val json = Json { ignoreUnknownKeys = false }

    fun lock(
        keyId: String,
        publicKey: X25519PublicKeyParameters,
        src: InputStream,
        dst: OutputStream,
        chunkSize: Int = DEFAULT_STREAM_CHUNK_SIZE,
        fileId: String? = null,
        chunkIndex: Int? = null,
    ): Map<String, Any?> {
        requireChunkSize(chunkSize)
        val recipientSpki = CryptoCodec.publicDer(publicKey)
        val ephemeral = CryptoCodec.generateKeyPair()
        val ephemeralPublic = ephemeral.generatePublicKey()
        val shared = CryptoCodec.exchange(ephemeral, publicKey)
        val hkdfSalt = CryptoCodec.randomBytes(32)
        val info = "hxdl.stream.v1:$keyId:".toByteArray() + sha256(recipientSpki)
        val contentKey = CryptoCodec.hkdf(shared, hkdfSalt, info)
        val headerBytes = headerJson(
            keyId,
            CryptoCodec.b64(CryptoCodec.publicDer(ephemeralPublic)),
            CryptoCodec.b64(hkdfSalt),
            chunkSize,
            fileId,
            chunkIndex,
        )
        if (headerBytes.size > MAX_STREAM_HEADER_BYTES) {
            throw DataLockException(DataLockErrorCode.INVALID_ARGUMENT, "stream header is too large")
        }
        val headerSha = CryptoCodec.sha256Base64Url(headerBytes)
        dst.write(byteArrayOf(0x48, 0x58, 0x44, 0x4c, 1))
        dst.write(intBytes(headerBytes.size))
        dst.write(headerBytes)

        var index = 0
        var total = 0
        val chunks = iterateChunks(src, chunkSize)
        for ((plaintext, isLast) in chunks) {
            val body = seal(contentKey, nonce(index, isLast), plaintext, aad(keyId, chunkSize, index, isLast, headerSha))
            dst.write(byteArrayOf(if (isLast) 1 else 0))
            dst.write(intBytes(body.size))
            dst.write(body)
            total += plaintext.size
            index += 1
        }
        return mapOf(
            "schema" to STREAM_SCHEMA,
            "recipientKeyId" to keyId,
            "chunkSize" to chunkSize,
            "chunkCount" to index,
            "plaintextLength" to total,
            "fileId" to fileId,
            "chunkIndex" to chunkIndex,
        )
    }

    fun open(
        keyId: String,
        readKey: X25519PrivateKeyParameters,
        recipientSpki: ByteArray,
        src: InputStream,
        dst: OutputStream,
    ): Map<String, Any?> {
        val magic = readExact(src, 4, "stream magic")
        if (!magic.contentEquals(byteArrayOf(0x48, 0x58, 0x44, 0x4c))) {
            throw DataLockException(DataLockErrorCode.TAMPERED_STREAM, "stream magic does not match hxdl.stream.v1")
        }
        val version = readExact(src, 1, "stream version")
        if (version[0] != 1.toByte()) {
            throw DataLockException(DataLockErrorCode.UNSUPPORTED_SCHEMA, "Unsupported stream version")
        }
        val headerLen = readInt(src, "stream header length")
        if (headerLen <= 0 || headerLen > MAX_STREAM_HEADER_BYTES) {
            throw DataLockException(DataLockErrorCode.TAMPERED_STREAM, "stream header length is invalid")
        }
        val headerBytes = readExact(src, headerLen, "stream header")
        val header = try {
            json.parseToJsonElement(headerBytes.toString(Charsets.UTF_8)).jsonObject
        } catch (ex: Exception) {
            throw DataLockException(DataLockErrorCode.TAMPERED_STREAM, "stream header is not JSON", ex)
        }
        if (header.string("schema") != STREAM_SCHEMA) {
            throw DataLockException(DataLockErrorCode.UNSUPPORTED_SCHEMA, "Unsupported stream schema")
        }
        if (header.string("recipientKeyId") != keyId) {
            throw DataLockException(DataLockErrorCode.ENVELOPE_RECIPIENT_MISMATCH, "stream recipient does not match the Keyring")
        }
        val alg = header["alg"]?.jsonObject
        if (alg?.string("kem") != "X25519" || alg.string("kdf") != "HKDF-SHA256" || alg.string("aead") != "AES-256-GCM" || alg.size != 3) {
            throw DataLockException(DataLockErrorCode.UNSUPPORTED_ALGORITHM, "stream must use X25519, HKDF-SHA256, and AES-256-GCM")
        }
        val chunkSize = header["chunkSize"]?.jsonPrimitive?.int
            ?: throw DataLockException(DataLockErrorCode.TAMPERED_STREAM, "stream chunkSize is invalid")
        requireChunkSize(chunkSize)
        val ephemeralSpki = CryptoCodec.fromB64(header.string("ephemeralPublicKey"), "ephemeralPublicKey", DataLockErrorCode.TAMPERED_STREAM, maxLength = 512)
        val hkdfSalt = CryptoCodec.fromB64(header.string("hkdfSalt"), "hkdfSalt", DataLockErrorCode.TAMPERED_STREAM, exactLength = 32)
        val ephemeralPublic = try {
            val info = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(ephemeralSpki)
            X25519PublicKeyParameters(info.publicKeyData.bytes, 0)
        } catch (ex: DataLockException) {
            throw ex
        } catch (ex: Exception) {
            throw DataLockException(DataLockErrorCode.TAMPERED_STREAM, "Invalid stream ephemeral public key", ex)
        }
        val shared = try {
            CryptoCodec.exchange(readKey, ephemeralPublic)
        } catch (ex: Exception) {
            throw DataLockException(DataLockErrorCode.TAMPERED_STREAM, "Invalid stream ephemeral public key", ex)
        }
        val info = "hxdl.stream.v1:$keyId:".toByteArray() + sha256(recipientSpki)
        val contentKey = CryptoCodec.hkdf(shared, hkdfSalt, info)
        val headerSha = CryptoCodec.sha256Base64Url(headerBytes)
        var index = 0
        var total = 0
        var sawLast = false
        while (true) {
            val flagRaw = src.read()
            if (flagRaw < 0) break
            if (sawLast) throw DataLockException(DataLockErrorCode.TAMPERED_STREAM, "stream continues after the last chunk")
            if (flagRaw != 0 && flagRaw != 1) throw DataLockException(DataLockErrorCode.TAMPERED_STREAM, "stream chunk flag is invalid")
            val isLast = flagRaw == 1
            val bodyLen = readInt(src, "chunk length")
            if (bodyLen < 16 || bodyLen > chunkSize + 16) {
                throw DataLockException(DataLockErrorCode.TAMPERED_STREAM, "stream chunk length is invalid")
            }
            val body = readExact(src, bodyLen, "chunk body")
            val plaintext = try {
                openChunk(contentKey, nonce(index, isLast), body, aad(keyId, chunkSize, index, isLast, headerSha))
            } catch (ex: DataLockException) {
                throw ex
            } catch (ex: Exception) {
                throw DataLockException(DataLockErrorCode.TAMPERED_STREAM, "stream chunk authentication failed", ex)
            }
            if (!isLast && plaintext.size != chunkSize) {
                throw DataLockException(DataLockErrorCode.TAMPERED_STREAM, "non-final stream chunk has an unexpected length")
            }
            if (isLast && plaintext.size > chunkSize) {
                throw DataLockException(DataLockErrorCode.TAMPERED_STREAM, "final stream chunk exceeds chunkSize")
            }
            dst.write(plaintext)
            total += plaintext.size
            index += 1
            sawLast = isLast
        }
        if (!sawLast) throw DataLockException(DataLockErrorCode.TAMPERED_STREAM, "stream ended before the last chunk")
        return mapOf(
            "schema" to STREAM_SCHEMA,
            "recipientKeyId" to keyId,
            "chunkSize" to chunkSize,
            "chunkCount" to index,
            "plaintextLength" to total,
            "fileId" to header["fileId"]?.jsonPrimitive?.content,
            "chunkIndex" to header["chunkIndex"]?.jsonPrimitive?.int,
        )
    }

    fun sealChunked(
        keyId: String,
        publicKey: X25519PublicKeyParameters,
        src: InputStream,
        chunkSize: Int,
        fileId: String,
        version: Int,
        previousManifest: Map<String, Any?>? = null,
        previousSealed: List<ByteArray>? = null,
    ): Pair<Map<String, Any?>, List<ByteArray>> {
        requireChunkSize(chunkSize)
        if ((previousManifest == null) != (previousSealed == null)) {
            throw DataLockException(DataLockErrorCode.INVALID_ARGUMENT, "previous manifest and sealed chunks must be passed together")
        }
        val previousByIndex = mutableMapOf<Int, Pair<ChunkEntry, ByteArray>>()
        if (previousManifest != null && previousSealed != null) {
            if (previousManifest["fileId"] != fileId) {
                throw DataLockException(DataLockErrorCode.INVALID_MANIFEST, "previous manifest belongs to a different file")
            }
            val entries = chunkList(previousManifest)
            if (entries.size != previousSealed.size) {
                throw DataLockException(DataLockErrorCode.INVALID_MANIFEST, "previous sealed chunk count does not match the manifest")
            }
            entries.forEachIndexed { index, entry ->
                val sealed = previousSealed[index]
                if (CryptoCodec.sha256Base64Url(sealed) != entry.sealedSha256) {
                    throw DataLockException(DataLockErrorCode.INVALID_MANIFEST, "previous sealed hash does not match the manifest")
                }
                previousByIndex[entry.index] = entry to sealed
            }
        }
        val chunks = mutableListOf<ByteArray>()
        val manifestChunks = mutableListOf<Map<String, Any?>>()
        var total = 0
        var index = 0
        while (true) {
            val (block, eof) = readUpTo(src, chunkSize)
            if (eof && block.isEmpty() && index > 0) break
            val digest = CryptoCodec.sha256Base64Url(block)
            val reused = previousByIndex[index]
            val sealed = if (reused != null && reused.first.plaintextSha256 == digest && reused.first.plaintextLength == block.size) {
                reused.second
            } else {
                val out = java.io.ByteArrayOutputStream()
                lock(keyId, publicKey, java.io.ByteArrayInputStream(block), out, chunkSize, fileId, index)
                out.toByteArray()
            }
            manifestChunks.add(
                mapOf(
                    "index" to index,
                    "plaintextLength" to block.size,
                    "plaintextSha256" to digest,
                    "sealedSha256" to CryptoCodec.sha256Base64Url(sealed),
                ),
            )
            chunks.add(sealed)
            total += block.size
            index += 1
            if (eof || block.size < chunkSize) break
        }
        val manifest = mapOf(
            "schema" to MANIFEST_SCHEMA,
            "fileId" to fileId,
            "version" to version,
            "chunkSize" to chunkSize,
            "totalPlaintextLength" to total,
            "chunks" to manifestChunks,
        )
        return manifest to chunks
    }

    fun openChunked(
        keyId: String,
        readKey: X25519PrivateKeyParameters,
        recipientSpki: ByteArray,
        manifest: Map<String, Any?>,
        sealedChunks: List<ByteArray>,
        dst: OutputStream,
    ): Map<String, Any?> {
        val entries = chunkList(manifest)
        if (entries.size != sealedChunks.size) {
            throw DataLockException(DataLockErrorCode.INVALID_MANIFEST, "sealed chunk count does not match the manifest")
        }
        var total = 0
        entries.forEachIndexed { index, entry ->
            val sealed = sealedChunks[index]
            if (CryptoCodec.sha256Base64Url(sealed) != entry.sealedSha256) {
                throw DataLockException(DataLockErrorCode.INVALID_MANIFEST, "sealed hash mismatch for chunk ${entry.index}")
            }
            val opened = java.io.ByteArrayOutputStream()
            val info = open(keyId, readKey, recipientSpki, java.io.ByteArrayInputStream(sealed), opened)
            val plaintext = opened.toByteArray()
            if (info["fileId"] != manifest["fileId"] || info["chunkIndex"] != entry.index) {
                throw DataLockException(DataLockErrorCode.INVALID_MANIFEST, "chunk ${entry.index} is bound to a different file")
            }
            if (plaintext.size != entry.plaintextLength || CryptoCodec.sha256Base64Url(plaintext) != entry.plaintextSha256) {
                throw DataLockException(DataLockErrorCode.TAMPERED_STREAM, "plaintext hash mismatch for chunk ${entry.index}")
            }
            dst.write(plaintext)
            total += plaintext.size
        }
        val expected = manifest["totalPlaintextLength"] as? Int
        if (expected != null && expected != total) {
            throw DataLockException(DataLockErrorCode.INVALID_MANIFEST, "manifest total length does not match the chunks")
        }
        return mapOf(
            "schema" to MANIFEST_SCHEMA,
            "fileId" to manifest["fileId"],
            "version" to manifest["version"],
            "plaintextLength" to total,
            "chunkCount" to entries.size,
        )
    }

    fun changedChunkIndexes(previous: Map<String, Any?>, current: Map<String, Any?>): List<Int> {
        val previousChunks = chunkList(previous)
        val currentChunks = chunkList(current)
        if (previous["fileId"] != current["fileId"]) {
            throw DataLockException(DataLockErrorCode.INVALID_MANIFEST, "manifests belong to different files")
        }
        val previousPlain = previousChunks.associate { it.index to it.plaintextSha256 }
        return currentChunks.filter { previousPlain[it.index] != it.plaintextSha256 }.map { it.index }
    }

    private data class ChunkEntry(val index: Int, val plaintextSha256: String, val sealedSha256: String, val plaintextLength: Int)

    private fun chunkList(manifest: Map<String, Any?>): List<ChunkEntry> {
        if (manifest["schema"] != MANIFEST_SCHEMA) {
            throw DataLockException(DataLockErrorCode.INVALID_MANIFEST, "manifest schema must be hxdl.manifest.v1")
        }
        val chunks = manifest["chunks"] as? List<*>
            ?: throw DataLockException(DataLockErrorCode.INVALID_MANIFEST, "manifest must list at least one chunk")
        return chunks.mapIndexed { expected, raw ->
            val entry = raw as? Map<*, *>
                ?: throw DataLockException(DataLockErrorCode.INVALID_MANIFEST, "manifest chunk indexes must be contiguous from 0")
            val index = entry["index"] as? Int
            if (index != expected) {
                throw DataLockException(DataLockErrorCode.INVALID_MANIFEST, "manifest chunk indexes must be contiguous from 0")
            }
            ChunkEntry(
                index,
                entry["plaintextSha256"] as? String
                    ?: throw DataLockException(DataLockErrorCode.INVALID_MANIFEST, "manifest chunk is missing plaintextSha256"),
                entry["sealedSha256"] as? String
                    ?: throw DataLockException(DataLockErrorCode.INVALID_MANIFEST, "manifest chunk is missing sealedSha256"),
                (entry["plaintextLength"] as? Number)?.toInt()
                    ?: throw DataLockException(DataLockErrorCode.INVALID_MANIFEST, "manifest chunk is missing plaintextLength"),
            )
        }
    }

    private fun iterateChunks(src: InputStream, chunkSize: Int): List<Pair<ByteArray, Boolean>> {
        val out = mutableListOf<Pair<ByteArray, Boolean>>()
        var previous = readUpTo(src, chunkSize)
        if (previous.second) {
            out.add(previous.first to true)
            return out
        }
        while (true) {
            val next = readUpTo(src, chunkSize)
            if (next.second && next.first.isEmpty()) {
                out.add(previous.first to true)
                break
            }
            out.add(previous.first to false)
            if (next.second) {
                out.add(next.first to true)
                break
            }
            previous = next
        }
        return out
    }

    private fun readUpTo(src: InputStream, size: Int): Pair<ByteArray, Boolean> {
        val buf = ByteArray(size)
        var filled = 0
        while (filled < size) {
            val n = src.read(buf, filled, size - filled)
            if (n < 0) return buf.copyOf(filled) to true
            filled += n
        }
        return buf to false
    }

    private fun seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        val sealed = CryptoCodec.aesGcmEncrypt(key, nonce, plaintext, aad)
        return sealed.ciphertext + sealed.tag
    }

    private fun openChunk(key: ByteArray, nonce: ByteArray, body: ByteArray, aad: ByteArray): ByteArray {
        val tag = body.copyOfRange(body.size - 16, body.size)
        val ciphertext = body.copyOfRange(0, body.size - 16)
        return CryptoCodec.aesGcmDecrypt(key, nonce, ciphertext, tag, aad)
    }

    private fun nonce(index: Int, isLast: Boolean): ByteArray {
        val nonce = ByteArray(12)
        val value = index.toLong()
        for (i in 7 downTo 0) {
            nonce[i] = ((value shr ((7 - i) * 8)) and 0xff).toByte()
        }
        nonce[11] = if (isLast) 1 else 0
        return nonce
    }

    private fun aad(keyId: String, chunkSize: Int, index: Int, isLast: Boolean, headerSha: String): ByteArray {
        val flag = if (isLast) "1" else "0"
        return "$STREAM_SCHEMA:$keyId:X25519:HKDF-SHA256:AES-256-GCM:$chunkSize:$index:$flag:$headerSha".toByteArray()
    }

    private fun headerJson(
        keyId: String,
        ephemeral: String,
        salt: String,
        chunkSize: Int,
        fileId: String?,
        chunkIndex: Int?,
    ): ByteArray {
        val builder = StringBuilder()
        builder.append("{\"schema\":").append(quote(STREAM_SCHEMA))
        builder.append(",\"recipientKeyId\":").append(quote(keyId))
        builder.append(",\"alg\":{\"kem\":\"X25519\",\"kdf\":\"HKDF-SHA256\",\"aead\":\"AES-256-GCM\"}")
        builder.append(",\"ephemeralPublicKey\":").append(quote(ephemeral))
        builder.append(",\"hkdfSalt\":").append(quote(salt))
        builder.append(",\"chunkSize\":").append(chunkSize)
        if (fileId != null) builder.append(",\"fileId\":").append(quote(fileId))
        if (chunkIndex != null) builder.append(",\"chunkIndex\":").append(chunkIndex)
        builder.append("}")
        return builder.toString().toByteArray(Charsets.UTF_8)
    }

    private fun quote(value: String): String {
        val escaped = buildString {
            append('"')
            for (ch in value) {
                when (ch) {
                    '\\' -> append("\\\\")
                    '"' -> append("\\\"")
                    else -> append(ch)
                }
            }
            append('"')
        }
        return escaped
    }

    private fun requireChunkSize(chunkSize: Int) {
        if (chunkSize < MIN_STREAM_CHUNK_SIZE || chunkSize > MAX_STREAM_CHUNK_SIZE) {
            throw DataLockException(
                DataLockErrorCode.INVALID_ARGUMENT,
                "chunk_size must be an integer from $MIN_STREAM_CHUNK_SIZE to $MAX_STREAM_CHUNK_SIZE",
            )
        }
    }

    private fun readExact(src: InputStream, size: Int, what: String): ByteArray {
        val buf = ByteArray(size)
        var filled = 0
        while (filled < size) {
            val n = src.read(buf, filled, size - filled)
            if (n < 0) throw DataLockException(DataLockErrorCode.TAMPERED_STREAM, "stream ended inside $what")
            filled += n
        }
        return buf
    }

    private fun readInt(src: InputStream, what: String): Int {
        val raw = readExact(src, 4, what)
        return ((raw[0].toInt() and 0xff) shl 24) or
            ((raw[1].toInt() and 0xff) shl 16) or
            ((raw[2].toInt() and 0xff) shl 8) or
            (raw[3].toInt() and 0xff)
    }

    private fun intBytes(value: Int): ByteArray = byteArrayOf(
        (value shr 24).toByte(),
        (value shr 16).toByte(),
        (value shr 8).toByte(),
        value.toByte(),
    )

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    private fun JsonObject.string(field: String): String? = this[field]?.jsonPrimitive?.content
}
