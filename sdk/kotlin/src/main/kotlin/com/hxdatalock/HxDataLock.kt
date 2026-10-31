package com.hxdatalock

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.Path

data class CreateKeyringOptions(
    val scryptN: Int = 262144,
    val allowWeakPassword: Boolean = false,
    val allowLowScryptN: Boolean = false,
    val publicKeyring: Boolean = false,
)

data class RewrapOptions(
    val allowWeakPassword: Boolean = false,
    val allowLowScryptN: Boolean = false,
    val publicKeyring: Boolean = false,
)

object HxDataLock {
    fun checkPasswordStrength(masterPassword: String): PasswordStrengthReport = PasswordStrength.check(masterPassword)

    fun changedChunkIndexes(previous: Map<String, Any?>, current: Map<String, Any?>): List<Int> =
        Stream.changedChunkIndexes(previous, current)

    fun createKeyring(masterPassword: String, options: CreateKeyringOptions = CreateKeyringOptions()): Keyring {
        val report = PasswordStrength.check(masterPassword)
        if (options.publicKeyring) {
            System.err.println(
                "DANGER: creating a Keyring for public storage. Anyone who can read it can guess the Master Password offline. Publish a Public Key Document instead unless this is deliberate.",
            )
        }
        if (options.publicKeyring && !report.allowedForPublicKeyring) {
            throw DataLockException(
                DataLockErrorCode.WEAK_MASTER_PASSWORD,
                "A public Keyring requires a Master Password of at least 80 estimated bits",
            )
        }
        if (!options.publicKeyring && !report.allowed && !options.allowWeakPassword) {
            throw DataLockException(
                DataLockErrorCode.WEAK_MASTER_PASSWORD,
                "Master Password is too weak to create a Keyring. Pass allowWeakPassword = true to create one anyway. Existing Keyrings can still be opened.",
            )
        }
        validateScryptN(options.scryptN)
        if (options.scryptN < MIN_CREATE_SCRYPT_N && !options.allowLowScryptN) {
            throw DataLockException(
                DataLockErrorCode.INSECURE_SCRYPT_PARAMETERS,
                "scrypt N ${options.scryptN} is below the create-time minimum $MIN_CREATE_SCRYPT_N. Readers still accept Keyrings down to $MIN_SCRYPT_N. Pass allowLowScryptN = true to create one anyway.",
            )
        }
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

    fun rewrapKeyring(
        keyring: Keyring,
        currentPassword: String,
        newPassword: String,
        options: RewrapOptions = RewrapOptions(),
    ): Keyring {
        keyring.verify()
        val report = PasswordStrength.check(newPassword)
        if (options.publicKeyring) {
            System.err.println(
                "DANGER: rewrapping a Keyring for public storage. Anyone who can read it can guess the Master Password offline. Publish a Public Key Document instead unless this is deliberate.",
            )
        }
        if (options.publicKeyring && !report.allowedForPublicKeyring) {
            throw DataLockException(
                DataLockErrorCode.WEAK_MASTER_PASSWORD,
                "A public Keyring requires a Master Password of at least 80 estimated bits",
            )
        }
        if (!options.publicKeyring && !report.allowed && !options.allowWeakPassword) {
            throw DataLockException(
                DataLockErrorCode.WEAK_MASTER_PASSWORD,
                "Master Password is too weak to rewrap a Keyring; pass allowWeakPassword = true to override",
            )
        }
        val encrypted = keyring.raw.mapField("encryptedReadKey", DataLockErrorCode.INVALID_KEYRING)
        val readKey = CryptoCodec.unwrapReadKey(encrypted, keyring.keyId, currentPassword)
        val previous = encrypted.mapField("kdf", DataLockErrorCode.INVALID_KEYRING)
        val previousN = jsonInt(previous["N"])
        val nextN = if (previousN < MIN_CREATE_SCRYPT_N && !options.allowLowScryptN) MIN_CREATE_SCRYPT_N else previousN
        val kdf = linkedMapOf<String, Any?>(
            "name" to "scrypt",
            "salt" to CryptoCodec.b64(CryptoCodec.randomBytes(32)),
            "N" to nextN,
            "r" to jsonInt(previous["r"]),
            "p" to jsonInt(previous["p"]),
            "keyLength" to KEY_LENGTH,
        )
        val rewrapped = Keyring(
            linkedMapOf(
                "schema" to KEYRING_SCHEMA,
                "createdAt" to keyring.raw["createdAt"],
                "publicWriteKey" to LinkedHashMap(keyring.publicWriteKey),
                "encryptedReadKey" to CryptoCodec.sealReadKey(keyring.keyId, newPassword, kdf, CryptoCodec.privateDer(readKey)),
            ),
        )
        rewrapped.verify()
        return rewrapped
    }

    fun makeUserDataLock(keyring: Keyring, masterPassword: String): UserDataLock {
        keyring.verify()
        return UserDataLock(keyring, CryptoCodec.unwrapReadKey(keyring.raw.mapField("encryptedReadKey", DataLockErrorCode.INVALID_KEYRING), keyring.keyId, masterPassword))
    }

    fun loadKeyring(path: Path): Keyring = Keyring.read(path)

    fun makeSenderDataLock(
        document: PublicKeyDocument,
        expectedKeyId: String? = null,
        allowUnpinnedPublicKey: Boolean = false,
    ): SenderDataLock {
        document.verify()
        if (expectedKeyId != null) {
            if (document.keyId != expectedKeyId) {
                throw DataLockException(DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT, "Public Key Document keyId does not match the expected keyId")
            }
        } else if (!allowUnpinnedPublicKey) {
            throw DataLockException(
                DataLockErrorCode.UNPINNED_PUBLIC_KEY,
                "Sender DataLock requires expectedKeyId so a replaced Public Key Document cannot be used by accident.",
            )
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

    fun lockStream(
        input: InputStream,
        output: OutputStream,
        chunkSize: Int = DEFAULT_STREAM_CHUNK_SIZE,
        fileId: String? = null,
        chunkIndex: Int? = null,
    ): Map<String, Any?> {
        document.verify()
        return Stream.lock(
            document.keyId,
            CryptoCodec.loadPublicWriteKey(document.raw, DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT),
            input,
            output,
            chunkSize,
            fileId,
            chunkIndex,
        )
    }

    fun sealChunked(
        input: InputStream,
        chunkSize: Int,
        fileId: String,
        version: Int = 1,
        previousManifest: Map<String, Any?>? = null,
        previousSealed: List<ByteArray>? = null,
    ): Pair<Map<String, Any?>, List<ByteArray>> {
        document.verify()
        return Stream.sealChunked(
            document.keyId,
            CryptoCodec.loadPublicWriteKey(document.raw, DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT),
            input,
            chunkSize,
            fileId,
            version,
            previousManifest,
            previousSealed,
        )
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

    fun lockStream(
        input: InputStream,
        output: OutputStream,
        chunkSize: Int = DEFAULT_STREAM_CHUNK_SIZE,
        fileId: String? = null,
        chunkIndex: Int? = null,
    ): Map<String, Any?> {
        requireOpenReadKey()
        keyring.verify()
        return Stream.lock(
            keyring.keyId,
            CryptoCodec.loadPublicWriteKey(keyring.raw, DataLockErrorCode.INVALID_KEYRING),
            input,
            output,
            chunkSize,
            fileId,
            chunkIndex,
        )
    }

    fun openChunked(
        manifest: Map<String, Any?>,
        sealedChunks: List<ByteArray>,
        output: OutputStream,
    ): Map<String, Any?> {
        val readKey = requireOpenReadKey()
        keyring.verify()
        val public = CryptoCodec.loadPublicWriteKey(keyring.raw, DataLockErrorCode.INVALID_KEYRING)
        return Stream.openChunked(keyring.keyId, readKey, CryptoCodec.publicDer(public), manifest, sealedChunks, output)
    }

    fun openStream(input: InputStream, output: OutputStream): Map<String, Any?> {
        val readKey = requireOpenReadKey()
        keyring.verify()
        val public = CryptoCodec.loadPublicWriteKey(keyring.raw, DataLockErrorCode.INVALID_KEYRING)
        return Stream.open(keyring.keyId, readKey, CryptoCodec.publicDer(public), input, output)
    }

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

private fun jsonInt(value: Any?): Int = when (value) {
    is Int -> value
    is Number -> value.toInt()
    else -> throw DataLockException(DataLockErrorCode.INVALID_KEYRING, "scrypt parameter is not an integer")
}

private fun validateScryptN(value: Int) {
    if (value < MIN_SCRYPT_N || value > MAX_SCRYPT_N || value and (value - 1) != 0) {
        throw DataLockException(
            DataLockErrorCode.INVALID_SCRYPT_PARAMS,
            "scrypt N must be a power of two between $MIN_SCRYPT_N and $MAX_SCRYPT_N",
        )
    }
}
