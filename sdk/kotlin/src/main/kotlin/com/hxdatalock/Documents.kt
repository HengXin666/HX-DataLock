package com.hxdatalock

import java.nio.file.Files
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions

private fun readJsonDocument(path: Path, maxBytes: Int): LinkedHashMap<String, Any?> {
    if (Files.size(path) > maxBytes) {
        throw DataLockException(DataLockErrorCode.OVERSIZED_FILE, "JSON document exceeds the v1 size limit")
    }
    return StableJson.parse(Files.readString(path))
}

private fun writeJsonDocument(path: Path, text: String) {
    // Converge an existing file's mode rather than only setting it at creation,
    // matching the Keyring writer and the other SDKs.
    if ("posix" in path.fileSystem.supportedFileAttributeViews()) {
        Files.writeString(path, text)
        Files.setPosixFilePermissions(path, setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE))
    } else {
        Files.writeString(path, text)
    }
}

private fun writePrivateJsonDocument(path: Path, text: String) {
    val permissions = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
    if ("posix" in path.fileSystem.supportedFileAttributeViews()) {
        try {
            Files.createFile(path, PosixFilePermissions.asFileAttribute(permissions))
        } catch (_: FileAlreadyExistsException) {
            Files.setPosixFilePermissions(path, permissions)
        }
        Files.writeString(path, text, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)
        Files.setPosixFilePermissions(path, permissions)
    } else {
        Files.writeString(path, text)
    }
}

data class Keyring(val raw: LinkedHashMap<String, Any?>) {
    val keyId: String get() = publicWriteKey["keyId"] as String
    internal val publicWriteKey: Map<String, Any?> get() = raw.mapField("publicWriteKey", DataLockErrorCode.INVALID_KEYRING)

    fun verify() {
        if (raw["schema"] != KEYRING_SCHEMA) {
            throw DataLockException(DataLockErrorCode.UNSUPPORTED_SCHEMA, "Unsupported Keyring schema: ${raw["schema"]}")
        }
        CryptoCodec.requireCreationTime(raw, DataLockErrorCode.INVALID_KEYRING)
        val encrypted = raw.mapField("encryptedReadKey", DataLockErrorCode.INVALID_KEYRING)
        CryptoCodec.validateKeyringEncryptedReadKey(encrypted)
        CryptoCodec.loadPublicWriteKey(raw, DataLockErrorCode.INVALID_KEYRING)
    }

    fun toJson(): String = StableJson.stringify(raw)

    fun write(path: Path) {
        writePrivateJsonDocument(path, toJson())
    }

    companion object {
        fun read(path: Path): Keyring {
            val keyring = Keyring(readJsonDocument(path, MAX_KEYRING_JSON_BYTES))
            keyring.verify()
            return keyring
        }
    }
}

data class DataEnvelope(val raw: LinkedHashMap<String, Any?>) {
    fun verify() {
        if (raw["schema"] != ENVELOPE_SCHEMA) {
            throw DataLockException(DataLockErrorCode.UNSUPPORTED_SCHEMA, "Unsupported Data Envelope schema: ${raw["schema"]}")
        }
        CryptoCodec.requireCreationTime(raw, DataLockErrorCode.TAMPERED_ENVELOPE)
        val alg = raw.mapField("alg", DataLockErrorCode.TAMPERED_ENVELOPE)
        if (alg != ENVELOPE_ALG) {
            throw DataLockException(DataLockErrorCode.UNSUPPORTED_ALGORITHM, "Data Envelope must use X25519, HKDF-SHA256, and AES-256-GCM")
        }
        CryptoCodec.validateEnvelopeFields(raw)
    }

    fun toJson(): String = StableJson.stringify(raw)

    fun write(path: Path) {
        writeJsonDocument(path, toJson())
    }

    companion object {
        fun read(path: Path): DataEnvelope {
            val envelope = DataEnvelope(readJsonDocument(path, MAX_ENVELOPE_JSON_BYTES))
            envelope.verify()
            return envelope
        }
    }
}

data class PublicKeyDocument(val raw: LinkedHashMap<String, Any?>) {
    val keyId: String get() = raw.mapField("publicWriteKey", DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT)["keyId"] as String

    fun verify() {
        if (raw["schema"] != PUBLIC_KEY_SCHEMA) {
            throw DataLockException(DataLockErrorCode.UNSUPPORTED_SCHEMA, "Unsupported Public Key Document schema: ${raw["schema"]}")
        }
        if (raw.containsKey("encryptedReadKey")) {
            throw DataLockException(DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT, "Public Key Document must not contain encrypted Read Key material")
        }
        CryptoCodec.requireCreationTime(raw, DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT)
        CryptoCodec.loadPublicWriteKey(raw, DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT)
    }

    fun toJson(): String = StableJson.stringify(raw)

    fun write(path: Path) {
        writeJsonDocument(path, toJson())
    }

    companion object {
        fun read(path: Path): PublicKeyDocument {
            val document = PublicKeyDocument(readJsonDocument(path, MAX_PUBLIC_KEY_JSON_BYTES))
            document.verify()
            return document
        }
    }
}

internal fun Map<String, Any?>.mapField(field: String, code: DataLockErrorCode): Map<String, Any?> =
    this[field] as? Map<String, Any?> ?: throw DataLockException(code, "Missing or invalid object field: $field")

/** Write decrypted bytes with owner-only permissions where the platform supports it. */
internal fun writePrivateJsonDocumentBytes(path: Path, payload: ByteArray) {
    val permissions = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
    if ("posix" in path.fileSystem.supportedFileAttributeViews()) {
        Files.write(path, payload)
        Files.setPosixFilePermissions(path, permissions)
    } else {
        Files.write(path, payload)
    }
}
