package com.hxdatalock

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

data class CreateKeyringOptions(val scryptN: Int = 262144)

object HxDataLock {
    fun createKeyring(masterPassword: String, options: CreateKeyringOptions = CreateKeyringOptions()): Keyring {
        validateScryptN(options.scryptN)
        val privateKey = CryptoCodec.generateKeyPair()
        val publicKey = privateKey.generatePublicKey()
        val publicDer = CryptoCodec.publicDer(publicKey)
        val privateDer = CryptoCodec.privateDer(privateKey)
        val keyId = "x25519:${CryptoCodec.sha256Base64Url(publicDer).take(22)}"
        val kdf = linkedMapOf<String, Any?>(
            "name" to "scrypt",
            "salt" to CryptoCodec.b64(CryptoCodec.randomBytes(32)),
            "N" to options.scryptN,
            "r" to DEFAULT_SCRYPT_R,
            "p" to DEFAULT_SCRYPT_P,
            "keyLength" to KEY_LENGTH,
        )
        val keyring = Keyring(
            linkedMapOf(
                "schema" to KEYRING_SCHEMA,
                "createdAt" to CryptoCodec.utcNow(),
                "publicWriteKey" to linkedMapOf(
                    "alg" to "X25519",
                    "keyId" to keyId,
                    "spki" to CryptoCodec.b64(publicDer),
                ),
                "encryptedReadKey" to CryptoCodec.sealReadKey(keyId, masterPassword, kdf, privateDer),
            )
        )
        keyring.verify()
        return keyring
    }

    fun makeUserDataLock(keyring: Keyring, masterPassword: String): UserDataLock {
        keyring.verify()
        return UserDataLock(keyring, CryptoCodec.unwrapReadKey(keyring.raw.mapField("encryptedReadKey", DataLockErrorCode.INVALID_KEYRING), keyring.keyId, masterPassword))
    }

    fun loadKeyring(path: Path): Keyring = Keyring.read(path)

    fun makeSenderDataLock(document: PublicKeyDocument, expectedKeyId: String? = null, requireExpectedKeyId: Boolean = false): SenderDataLock {
        document.verify()
        if (expectedKeyId != null) {
            if (document.keyId != expectedKeyId) {
                throw DataLockException(DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT, "Public Key Document keyId does not match the expected keyId")
            }
        } else if (requireExpectedKeyId) {
            throw DataLockException(DataLockErrorCode.UNPINNED_PUBLIC_KEY, "Sender DataLock requires expectedKeyId so a replaced Public Key Document is rejected")
        }
        return SenderDataLock(document)
    }

    fun exportPublicKeyDocument(keyring: Keyring): PublicKeyDocument {
        keyring.verify()
        val document = PublicKeyDocument(
            linkedMapOf(
                "schema" to PUBLIC_KEY_SCHEMA,
                "createdAt" to CryptoCodec.utcNow(),
                "publicWriteKey" to LinkedHashMap(keyring.publicWriteKey),
            )
        )
        document.verify()
        return document
    }
}

class SenderDataLock internal constructor(
    private val document: PublicKeyDocument,
) {
    fun lockBytes(payloadBytes: ByteArray): DataEnvelope {
        if (payloadBytes.size > MAX_V1_FILE_BYTES) {
            throw DataLockException(DataLockErrorCode.OVERSIZED_FILE, "V1 Full Data Envelopes support payloads up to 25 MB")
        }
        document.verify()
        return DataEnvelope(
            CryptoCodec.lockBytesWithPublicKey(
                document.keyId,
                CryptoCodec.loadPublicWriteKey(document.raw, DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT),
                payloadBytes,
            ),
        )
    }

    fun lockText(text: String): DataEnvelope = lockBytes(encodeStrictUtf8(text))

    fun lockFile(inputPath: Path, outputPath: Path): DataEnvelope {
        if (Files.size(inputPath) > MAX_V1_FILE_BYTES) {
            throw DataLockException(DataLockErrorCode.OVERSIZED_FILE, "V1 Full Data Envelopes support local files up to 25 MB")
        }
        val envelope = lockBytes(Files.readAllBytes(inputPath))
        envelope.write(outputPath)
        return envelope
    }
}

class UserDataLock internal constructor(
    private val keyring: Keyring,
    private var readKey: X25519PrivateKeyParameters?,
) : AutoCloseable {
    fun openBytes(envelope: DataEnvelope): ByteArray {
        val currentReadKey = requireOpenReadKey()
        keyring.verify()
        envelope.verify()
        if (envelope.raw["recipientKeyId"] != keyring.keyId) {
            throw DataLockException(DataLockErrorCode.ENVELOPE_RECIPIENT_MISMATCH, "Data Envelope recipient does not match the Keyring")
        }
        return CryptoCodec.openEnvelopePayload(keyring.keyId, currentReadKey, envelope.raw)
    }

    fun openText(envelope: DataEnvelope): String {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(openBytes(envelope)))
                .toString()
        } catch (ex: CharacterCodingException) {
            throw DataLockException(DataLockErrorCode.INVALID_UTF8, "Data Envelope payload is not valid UTF-8", ex)
        }
    }

    fun openFile(inputPath: Path, outputPath: Path): ByteArray {
        val plaintext = openBytes(DataEnvelope.read(inputPath))
        if (plaintext.size > MAX_V1_FILE_BYTES) {
            throw DataLockException(DataLockErrorCode.OVERSIZED_FILE, "V1 Full Data Envelopes support local files up to 25 MB")
        }
        // A decrypted payload is as sensitive as the Keyring, so it must not
        // follow a permissive umask.
        writePrivateJsonDocumentBytes(outputPath, plaintext)
        return plaintext
    }

    fun lockBytes(payloadBytes: ByteArray): DataEnvelope {
        requireOpenReadKey()
        // Enforce the v1 limit here, not only in lockFile, so this SDK cannot
        // emit a Full Data Envelope that every reader refuses to open.
        if (payloadBytes.size > MAX_V1_FILE_BYTES) {
            throw DataLockException(DataLockErrorCode.OVERSIZED_FILE, "V1 Full Data Envelopes support payloads up to 25 MB")
        }
        keyring.verify()
        return DataEnvelope(CryptoCodec.lockBytesWithPublicKey(keyring.keyId, CryptoCodec.loadPublicWriteKey(keyring.raw, DataLockErrorCode.INVALID_KEYRING), payloadBytes))
    }

    fun lockText(text: String): DataEnvelope = lockBytes(encodeStrictUtf8(text))

    fun lockFile(inputPath: Path, outputPath: Path): DataEnvelope {
        if (Files.size(inputPath) > MAX_V1_FILE_BYTES) {
            throw DataLockException(DataLockErrorCode.OVERSIZED_FILE, "V1 Full Data Envelopes support local files up to 25 MB")
        }
        val envelope = lockBytes(Files.readAllBytes(inputPath))
        envelope.write(outputPath)
        return envelope
    }

    override fun close() {
        readKey = null
    }

    private fun requireOpenReadKey(): X25519PrivateKeyParameters =
        readKey ?: throw DataLockException(DataLockErrorCode.DATALOCK_CLOSED, "User DataLock is closed")
}

internal fun encodeStrictUtf8(text: String): ByteArray {
    try {
        val encoded = StandardCharsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .encode(CharBuffer.wrap(text))
        val out = ByteArray(encoded.remaining())
        encoded.get(out)
        return out
    } catch (ex: CharacterCodingException) {
        throw DataLockException(DataLockErrorCode.INVALID_UTF8, "Text is not valid UTF-8", ex)
    }
}

private fun validateScryptN(value: Int) {
    if (value < MIN_SCRYPT_N || value > MAX_SCRYPT_N || value and (value - 1) != 0) {
        throw DataLockException(
            DataLockErrorCode.INVALID_SCRYPT_PARAMS,
            "scrypt N must be a power of two between $MIN_SCRYPT_N and $MAX_SCRYPT_N",
        )
    }
}
