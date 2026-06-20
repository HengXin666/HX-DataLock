package com.hxdatalock

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class HxDataLockTest {
    @Test
    fun userCanCreateKeyringLockOpenAndClose() {
        val password = "correct horse battery staple for hx datalock"
        val keyring = HxDataLock.createKeyring(password, CreateKeyringOptions(scryptN = 16384))
        val user = HxDataLock.makeUserDataLock(keyring, password)

        val envelope = user.lockBytes("kotlin local payload".encodeToByteArray())

        assertContentEquals("kotlin local payload".encodeToByteArray(), user.openBytes(envelope))

        user.close()
        val closed = assertFailsWith<DataLockException> {
            user.openBytes(envelope)
        }
        assertEquals(DataLockErrorCode.WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING, closed.code)
    }

    @Test
    fun masterPasswordUsesNfcNormalizationForUnlock() {
        val decomposedPassword = "Cafe\u0301 passphrase for hx datalock"
        val composedPassword = "Caf\u00e9 passphrase for hx datalock"
        val keyring = HxDataLock.createKeyring(decomposedPassword, CreateKeyringOptions(scryptN = 16384))
        val user = HxDataLock.makeUserDataLock(keyring, composedPassword)

        val envelope = user.lockText("nfc unlock")

        assertEquals("nfc unlock", user.openText(envelope))
    }

    @Test
    fun readsDocumentsByFieldAndWritesStableJson() {
        val keyring = HxDataLock.createKeyring("correct horse battery staple for hx datalock", CreateKeyringOptions(scryptN = 16384))
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
    fun expectedFailuresUseStableErrorCodes() {
        val password = "correct horse battery staple for hx datalock"
        val keyring = HxDataLock.createKeyring(password, CreateKeyringOptions(scryptN = 16384))
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

        val secondKeyring = HxDataLock.createKeyring("another correct horse battery staple", CreateKeyringOptions(scryptN = 16384))
        val secondUser = HxDataLock.makeUserDataLock(secondKeyring, "another correct horse battery staple")
        val mismatch = assertFailsWith<DataLockException> {
            secondUser.openBytes(envelope)
        }
        assertEquals(DataLockErrorCode.ENVELOPE_RECIPIENT_MISMATCH, mismatch.code)
    }

    @Test
    fun v1ScopeDoesNotExposeSenderDataLock() {
        val publicMembers = HxDataLock::class.members.map { it.name }.toSet()

        assertFalse(publicMembers.contains("makeSenderDataLock"))
    }
}
