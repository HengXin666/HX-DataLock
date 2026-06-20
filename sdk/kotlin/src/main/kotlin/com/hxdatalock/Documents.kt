package com.hxdatalock

import java.nio.file.Files
import java.nio.file.Path

data class Keyring(val raw: LinkedHashMap<String, Any?>) {
    val keyId: String get() = publicWriteKey["keyId"] as String
    internal val publicWriteKey: Map<String, Any?> get() = raw.mapField("publicWriteKey", DataLockErrorCode.INVALID_KEYRING)

    fun verify() {
        if (raw["schema"] != KEYRING_SCHEMA) {
            throw DataLockException(DataLockErrorCode.UNSUPPORTED_SCHEMA, "Unsupported Keyring schema: ${raw["schema"]}")
        }
        val encrypted = raw.mapField("encryptedReadKey", DataLockErrorCode.INVALID_KEYRING)
        val kdf = encrypted.mapField("kdf", DataLockErrorCode.INVALID_KEYRING)
        val aead = encrypted.mapField("aead", DataLockErrorCode.INVALID_KEYRING)
        if (kdf["name"] != "scrypt") {
            throw DataLockException(DataLockErrorCode.UNSUPPORTED_ALGORITHM, "Unsupported password KDF: ${kdf["name"]}")
        }
        if (aead["name"] != "AES-256-GCM") {
            throw DataLockException(DataLockErrorCode.UNSUPPORTED_ALGORITHM, "encryptedReadKey must use AES-256-GCM")
        }
        CryptoCodec.loadPublicWriteKey(raw, DataLockErrorCode.INVALID_KEYRING)
    }

    fun toJson(): String = StableJson.stringify(raw)

    fun write(path: Path) {
        Files.writeString(path, toJson())
    }

    companion object {
        fun read(path: Path): Keyring {
            val keyring = Keyring(StableJson.parse(Files.readString(path)))
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
        val alg = raw.mapField("alg", DataLockErrorCode.TAMPERED_ENVELOPE)
        if (alg != ENVELOPE_ALG) {
            throw DataLockException(DataLockErrorCode.UNSUPPORTED_ALGORITHM, "Data Envelope must use X25519, HKDF-SHA256, and AES-256-GCM")
        }
    }

    fun toJson(): String = StableJson.stringify(raw)

    fun write(path: Path) {
        Files.writeString(path, toJson())
    }

    companion object {
        fun read(path: Path): DataEnvelope = DataEnvelope(StableJson.parse(Files.readString(path)))
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
        CryptoCodec.loadPublicWriteKey(raw, DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT)
    }

    fun toJson(): String = StableJson.stringify(raw)

    fun write(path: Path) {
        Files.writeString(path, toJson())
    }

    companion object {
        fun read(path: Path): PublicKeyDocument {
            val document = PublicKeyDocument(StableJson.parse(Files.readString(path)))
            document.verify()
            return document
        }
    }
}

internal fun Map<String, Any?>.mapField(field: String, code: DataLockErrorCode): Map<String, Any?> =
    this[field] as? Map<String, Any?> ?: throw DataLockException(code, "Missing or invalid object field: $field")
