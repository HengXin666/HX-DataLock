package com.hxdatalock

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission

class HxDataLockTest {
    @Test
    fun userCanCreateKeyringLockOpenAndClose() {
        val password = "correct horse battery staple for hx datalock"
        val keyring = HxDataLock.createKeyring(password, CreateKeyringOptions(scryptN = 16384, allowLowScryptN = true))
        val user = HxDataLock.makeUserDataLock(keyring, password)

        val envelope = user.lockBytes("kotlin local payload".encodeToByteArray())

        assertContentEquals("kotlin local payload".encodeToByteArray(), user.openBytes(envelope))

        user.close()
        val closed = assertFailsWith<DataLockException> {
            user.openBytes(envelope)
        }
        assertEquals(DataLockErrorCode.DATALOCK_CLOSED, closed.code)
    }

    @Test
    fun senderLocksFromPublicDocumentAndEnvelopeParsesFromString() {
        val password = "correct horse battery staple for hx datalock"
        val keyring = HxDataLock.createKeyring(password, CreateKeyringOptions(scryptN = 16384, allowLowScryptN = true))
        val document = HxDataLock.exportPublicKeyDocument(keyring)
        val sender = HxDataLock.makeSenderDataLock(document, expectedKeyId = document.keyId)
        val envelope = sender.lockText("from sender")
        val parsed = DataEnvelope.parse(envelope.toJson())
        assertEquals(document.keyId, parsed.inspect()["recipientKeyId"])
        val user = HxDataLock.makeUserDataLock(keyring, password)
        assertEquals("from sender", user.openText(parsed))
        val surrogate = assertFailsWith<DataLockException> { sender.lockText("bad\uD800") }
        assertEquals(DataLockErrorCode.INVALID_UTF8, surrogate.code)
    }

    @Test
    fun masterPasswordUsesNfcNormalizationForUnlock() {
        val decomposedPassword = "Cafe\u0301 passphrase for hx datalock"
        val composedPassword = "Caf\u00e9 passphrase for hx datalock"
        val keyring = HxDataLock.createKeyring(decomposedPassword, CreateKeyringOptions(scryptN = 16384, allowLowScryptN = true))
        val user = HxDataLock.makeUserDataLock(keyring, composedPassword)

        val envelope = user.lockText("nfc unlock")

        assertEquals("nfc unlock", user.openText(envelope))
    }

    @Test
    fun readsDocumentsByFieldAndWritesStableJson() {
        val keyring = HxDataLock.createKeyring("correct horse battery staple for hx datalock", CreateKeyringOptions(scryptN = 16384, allowLowScryptN = true))
        val publicKeyDocument = HxDataLock.exportPublicKeyDocument(keyring)
        val user = HxDataLock.makeUserDataLock(keyring, "correct horse battery staple for hx datalock")
        val envelope = user.lockText("stable json")

        assertEquals(listOf("schema", "createdAt", "publicWriteKey", "encryptedReadKey"), keyring.raw.keys.toList())
        assertEquals(listOf("schema", "createdAt", "publicWriteKey"), publicKeyDocument.raw.keys.toList())
        assertFalse(publicKeyDocument.raw.containsKey("encryptedReadKey"))
        assertEquals(listOf("schema", "createdAt", "recipientKeyId", "alg", "ephemeralPublicKey", "hkdfSalt", "nonce", "tag", "ciphertext"), envelope.raw.keys.toList())
        assertEquals("stable json", user.openText(DataEnvelope(StableJson.parse(envelope.toJson()))))
    }

    @Test
    fun keyringWriteConvergesToOwnerReadWritePermissionsOnPosixFileSystems() {
        val path = Files.createTempFile("hxdl-keyring", ".json")
        try {
            if ("posix" !in path.fileSystem.supportedFileAttributeViews()) return
            val keyring = HxDataLock.createKeyring("correct horse battery staple for hx datalock", CreateKeyringOptions(scryptN = 16384, allowLowScryptN = true))
            Files.writeString(path, "{}")
            Files.setPosixFilePermissions(
                path,
                setOf(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.GROUP_READ,
                    PosixFilePermission.OTHERS_READ,
                ),
            )

            keyring.write(path)

            assertEquals(
                setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                Files.getPosixFilePermissions(path),
            )
        } finally {
            Files.deleteIfExists(path)
        }
    }

    @Test
    fun expectedFailuresUseStableErrorCodes() {
        val password = "correct horse battery staple for hx datalock"
        val keyring = HxDataLock.createKeyring(password, CreateKeyringOptions(scryptN = 16384, allowLowScryptN = true))
        val user = HxDataLock.makeUserDataLock(keyring, password)
        val envelope = user.lockText("stable error codes")

        val wrongPassword = assertFailsWith<DataLockException> {
            HxDataLock.makeUserDataLock(keyring, "wrong password")
        }
        assertEquals(DataLockErrorCode.WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING, wrongPassword.code)

        val tamperedEnvelope = assertFailsWith<DataLockException> {
            user.openBytes(DataEnvelope(LinkedHashMap(envelope.raw).also { it["ciphertext"] = "AAAA" }))
        }
        assertEquals(DataLockErrorCode.TAMPERED_ENVELOPE, tamperedEnvelope.code)

        val unsupportedSchema = assertFailsWith<DataLockException> {
            user.openBytes(DataEnvelope(LinkedHashMap(envelope.raw).also { it["schema"] = "hxdl.envelope.v2" }))
        }
        assertEquals(DataLockErrorCode.UNSUPPORTED_SCHEMA, unsupportedSchema.code)

        val unsupportedAlgorithm = assertFailsWith<DataLockException> {
            @Suppress("UNCHECKED_CAST")
            val alg = LinkedHashMap(envelope.raw["alg"] as Map<String, Any?>)
            alg["aead"] = "ChaCha20-Poly1305"
            user.openBytes(DataEnvelope(LinkedHashMap(envelope.raw).also { it["alg"] = alg }))
        }
        assertEquals(DataLockErrorCode.UNSUPPORTED_ALGORITHM, unsupportedAlgorithm.code)

        val secondKeyring = HxDataLock.createKeyring("another correct horse battery staple", CreateKeyringOptions(scryptN = 16384, allowLowScryptN = true))
        val secondUser = HxDataLock.makeUserDataLock(secondKeyring, "another correct horse battery staple")
        val mismatch = assertFailsWith<DataLockException> {
            secondUser.openBytes(envelope)
        }
        assertEquals(DataLockErrorCode.ENVELOPE_RECIPIENT_MISMATCH, mismatch.code)
    }

    @Test
    fun rejectsHardenedUntrustedInputs() {
        val password = "correct horse battery staple for hx datalock"
        val keyring = HxDataLock.createKeyring(password, CreateKeyringOptions(scryptN = 16384, allowLowScryptN = true))
        val user = HxDataLock.makeUserDataLock(keyring, password)
        val envelope = user.lockBytes("hello".encodeToByteArray())

        @Suppress("UNCHECKED_CAST")
        val oversizedKdf = LinkedHashMap(keyring.raw).also { raw ->
            val encrypted = LinkedHashMap(raw["encryptedReadKey"] as Map<String, Any?>)
            val kdf = LinkedHashMap(encrypted["kdf"] as Map<String, Any?>)
            kdf["N"] = 1 shl 30
            encrypted["kdf"] = kdf
            raw["encryptedReadKey"] = encrypted
        }
        val invalidKdf = assertFailsWith<DataLockException> {
            Keyring(oversizedKdf).verify()
        }
        assertEquals(DataLockErrorCode.INVALID_KEYRING, invalidKdf.code)

        val shortNonce = assertFailsWith<DataLockException> {
            DataEnvelope(LinkedHashMap(envelope.raw).also { it["nonce"] = "AAAA" }).verify()
        }
        assertEquals(DataLockErrorCode.TAMPERED_ENVELOPE, shortNonce.code)

        val maxB64Chars = ((MAX_V1_FILE_BYTES + 2) / 3) * 4
        val oversizedCiphertext = assertFailsWith<DataLockException> {
            DataEnvelope(LinkedHashMap(envelope.raw).also { it["ciphertext"] = "A".repeat(maxB64Chars + 4) }).verify()
        }
        assertEquals(DataLockErrorCode.OVERSIZED_FILE, oversizedCiphertext.code)
    }

    @Test
    fun passwordStrengthMatchesTheSharedRefusalPolicy() {
        val weak = HxDataLock.checkPasswordStrength("password")
        assertEquals("weak", weak.level)
        assertFalse(weak.allowed)
        assertTrue(weak.score <= 1)
        val strong = HxDataLock.checkPasswordStrength("correct horse battery staple for hx datalock")
        assertTrue(strong.allowed)
        assertTrue(strong.level == "good" || strong.level == "strong")
    }

    @Test
    fun streamRoundTripRejectsTruncation() {
        val password = "correct horse battery staple for hx datalock"
        val keyring = HxDataLock.createKeyring(password, CreateKeyringOptions(scryptN = 16384, allowLowScryptN = true))
        val document = HxDataLock.exportPublicKeyDocument(keyring)
        val sender = HxDataLock.makeSenderDataLock(document, expectedKeyId = document.keyId)
        val payload = ByteArray(100) { it.toByte() }
        val sealed = ByteArrayOutputStream()
        val info = sender.lockStream(ByteArrayInputStream(payload), sealed, chunkSize = 32)
        assertEquals(100, info["plaintextLength"])
        val user = HxDataLock.makeUserDataLock(keyring, password)
        val opened = ByteArrayOutputStream()
        user.openStream(ByteArrayInputStream(sealed.toByteArray()), opened)
        assertContentEquals(payload, opened.toByteArray())
        val truncated = sealed.toByteArray().copyOf(sealed.size() - 8)
        val rejected = assertFailsWith<DataLockException> {
            user.openStream(ByteArrayInputStream(truncated), ByteArrayOutputStream())
        }
        assertEquals(DataLockErrorCode.TAMPERED_STREAM, rejected.code)
    }

    @Test
    fun sealChunkedReusesUnchangedChunksAndRejectsABadPin() {
        val password = "correct horse battery staple for hx datalock"
        val keyring = HxDataLock.createKeyring(password, CreateKeyringOptions(scryptN = 16384, allowLowScryptN = true))
        val document = HxDataLock.exportPublicKeyDocument(keyring)
        val mismatch = assertFailsWith<DataLockException> {
            HxDataLock.makeSenderDataLock(document, expectedKeyId = "x25519:not-the-key")
        }
        assertEquals(DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT, mismatch.code)
        val unpinned = assertFailsWith<DataLockException> {
            HxDataLock.makeSenderDataLock(document)
        }
        assertEquals(DataLockErrorCode.UNPINNED_PUBLIC_KEY, unpinned.code)
        val sender = HxDataLock.makeSenderDataLock(document, expectedKeyId = document.keyId)
        val first = sender.sealChunked(ByteArrayInputStream(ByteArray(80) { 1 }), 40, "file-a", 1)
        val second = sender.sealChunked(
            ByteArrayInputStream(ByteArray(40) { 1 } + ByteArray(40) { 2 }),
            40,
            "file-a",
            2,
            first.first,
            first.second,
        )
        assertEquals(listOf(1), HxDataLock.changedChunkIndexes(first.first, second.first))
        assertContentEquals(first.second[0], second.second[0])
        val user = HxDataLock.makeUserDataLock(keyring, password)
        val opened = ByteArrayOutputStream()
        user.openChunked(second.first, second.second, opened)
        assertEquals(80, opened.size())
    }

    @Test
    fun senderDataLockIsPartOfThePublicSurface() {
        val publicMembers = HxDataLock::class.java.methods.map { it.name }.toSet()

        assertTrue(publicMembers.contains("makeSenderDataLock"))
    }

    @Test
    fun weakMasterPasswordDoesNotCreateAKeyringUnlessAllowed() {
        val rejected = assertFailsWith<DataLockException> {
            HxDataLock.createKeyring("password", CreateKeyringOptions(scryptN = 16384, allowLowScryptN = true))
        }
        assertEquals(DataLockErrorCode.WEAK_MASTER_PASSWORD, rejected.code)

        val keyring = HxDataLock.createKeyring(
            "password",
            CreateKeyringOptions(scryptN = 16384, allowLowScryptN = true, allowWeakPassword = true),
        )
        val user = HxDataLock.makeUserDataLock(keyring, "password")
        assertEquals("still opens", user.openText(user.lockText("still opens")))
    }

    @Test
    fun createRejectsScryptNBelowTheCreateFloor() {
        val rejected = assertFailsWith<DataLockException> {
            HxDataLock.createKeyring("correct horse battery staple for hx datalock", CreateKeyringOptions(scryptN = 16384))
        }
        assertEquals(DataLockErrorCode.INSECURE_SCRYPT_PARAMETERS, rejected.code)

        val keyring = HxDataLock.createKeyring(
            "correct horse battery staple for hx datalock",
            CreateKeyringOptions(scryptN = 16384, allowLowScryptN = true),
        )
        val user = HxDataLock.makeUserDataLock(keyring, "correct horse battery staple for hx datalock")
        assertEquals("legacy", user.openText(user.lockText("legacy")))
    }
}
