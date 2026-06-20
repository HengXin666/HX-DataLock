package com.hxdatalock

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.generators.SCrypt
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Security
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.text.Normalizer
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object CryptoCodec {
    private val random = SecureRandom()
    private val b64 = Base64.getEncoder()
    private val b64Decoder = Base64.getDecoder()
    private val b64Url = Base64.getUrlEncoder().withoutPadding()

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    fun b64(data: ByteArray): String = b64.encodeToString(data)

    fun fromB64(value: Any?, field: String, code: DataLockErrorCode): ByteArray {
        if (value !is String) {
            throw DataLockException(code, "Missing or invalid base64 field: $field")
        }
        try {
            return b64Decoder.decode(value)
        } catch (ex: IllegalArgumentException) {
            throw DataLockException(code, "Missing or invalid base64 field: $field", ex)
        }
    }

    fun utcNow(): String = DateTimeFormatter.ISO_INSTANT.format(Instant.now())

    fun sha256Base64Url(data: ByteArray): String = b64Url.encodeToString(MessageDigest.getInstance("SHA-256").digest(data))

    fun generateKeyPair(): X25519PrivateKeyParameters {
        val privateKey = X25519PrivateKeyParameters(random)
        return privateKey
    }

    fun publicDer(publicKey: X25519PublicKeyParameters): ByteArray = SubjectPublicKeyInfoFactory.fromRaw(publicKey.encoded).encoded

    fun privateDer(privateKey: X25519PrivateKeyParameters): ByteArray = PrivateKeyInfoFactory.fromRaw(privateKey.encoded).encoded

    fun loadPublicWriteKey(raw: Map<String, Any?>, code: DataLockErrorCode): X25519PublicKeyParameters {
        val publicWriteKey = raw.mapField("publicWriteKey", code)
        if (publicWriteKey["alg"] != "X25519") {
            throw DataLockException(DataLockErrorCode.UNSUPPORTED_ALGORITHM, "publicWriteKey must use X25519")
        }
        try {
            val publicDer = fromB64(publicWriteKey["spki"], "publicWriteKey.spki", code)
            val expectedKeyId = "x25519:${sha256Base64Url(publicDer).take(22)}"
            if (publicWriteKey["keyId"] != expectedKeyId) {
                throw DataLockException(code, "keyId does not match the Write Key")
            }
            val info = SubjectPublicKeyInfo.getInstance(publicDer)
            return X25519PublicKeyParameters(info.publicKeyData.bytes, 0)
        } catch (ex: DataLockException) {
            throw ex
        } catch (ex: Exception) {
            throw DataLockException(code, "Invalid public Write Key", ex)
        }
    }

    fun loadPrivateReadKey(privateDer: ByteArray): X25519PrivateKeyParameters {
        try {
            val info = PrivateKeyInfo.getInstance(privateDer)
            val raw = ASN1OctetString.getInstance(info.parsePrivateKey()).octets
            return X25519PrivateKeyParameters(raw, 0)
        } catch (ex: Exception) {
            throw DataLockException(DataLockErrorCode.INVALID_KEYRING, "Unwrapped Read Key is not an X25519 private key", ex)
        }
    }

    fun derivePasswordKey(masterPassword: String, kdf: Map<String, Any?>): ByteArray {
        if (kdf["name"] != "scrypt") {
            throw DataLockException(DataLockErrorCode.UNSUPPORTED_ALGORITHM, "Unsupported password KDF: ${kdf["name"]}")
        }
        val normalized = Normalizer.normalize(masterPassword, Normalizer.Form.NFC)
        return SCrypt.generate(
            normalized.toByteArray(Charsets.UTF_8),
            fromB64(kdf["salt"], "encryptedReadKey.kdf.salt", DataLockErrorCode.INVALID_KEYRING),
            (kdf["N"] as Number).toInt(),
            (kdf["r"] as Number).toInt(),
            (kdf["p"] as Number).toInt(),
            (kdf["keyLength"] as Number?)?.toInt() ?: KEY_LENGTH,
        )
    }

    fun sealReadKey(keyId: String, masterPassword: String, kdf: Map<String, Any?>, privateDer: ByteArray): LinkedHashMap<String, Any?> {
        val wrappingKey = derivePasswordKey(masterPassword, kdf)
        val nonce = randomBytes(12)
        val sealed = aesGcmEncrypt(wrappingKey, nonce, privateDer, keyringAad(keyId))
        return linkedMapOf(
            "kdf" to kdf,
            "aead" to linkedMapOf(
                "name" to "AES-256-GCM",
                "nonce" to b64(nonce),
                "tag" to b64(sealed.tag),
            ),
            "ciphertext" to b64(sealed.ciphertext),
        )
    }

    fun unwrapReadKey(encrypted: Map<String, Any?>, keyId: String, masterPassword: String): X25519PrivateKeyParameters {
        val wrappingKey = derivePasswordKey(masterPassword, encrypted.mapField("kdf", DataLockErrorCode.INVALID_KEYRING))
        val aead = encrypted.mapField("aead", DataLockErrorCode.INVALID_KEYRING)
        try {
            val privateDer = aesGcmDecrypt(
                wrappingKey,
                fromB64(aead["nonce"], "encryptedReadKey.aead.nonce", DataLockErrorCode.INVALID_KEYRING),
                fromB64(encrypted["ciphertext"], "encryptedReadKey.ciphertext", DataLockErrorCode.INVALID_KEYRING),
                fromB64(aead["tag"], "encryptedReadKey.aead.tag", DataLockErrorCode.INVALID_KEYRING),
                keyringAad(keyId),
            )
            return loadPrivateReadKey(privateDer)
        } catch (ex: DataLockException) {
            throw ex
        } catch (ex: Exception) {
            throw DataLockException(DataLockErrorCode.WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING, "Wrong master password or tampered Keyring", ex)
        }
    }

    fun lockBytesWithPublicKey(keyId: String, publicWriteKey: X25519PublicKeyParameters, payload: ByteArray): LinkedHashMap<String, Any?> {
        val ephemeralPrivate = X25519PrivateKeyParameters(random)
        val ephemeralPublic = ephemeralPrivate.generatePublicKey()
        val sharedSecret = exchange(ephemeralPrivate, publicWriteKey)
        val hkdfSalt = randomBytes(32)
        val contentKey = hkdf(sharedSecret, hkdfSalt, "$ENVELOPE_SCHEMA:$keyId".toByteArray(Charsets.UTF_8))
        val nonce = randomBytes(12)
        val sealed = aesGcmEncrypt(contentKey, nonce, payload, envelopeAad(keyId, ENVELOPE_ALG))
        return linkedMapOf(
            "schema" to ENVELOPE_SCHEMA,
            "createdAt" to utcNow(),
            "recipientKeyId" to keyId,
            "alg" to LinkedHashMap(ENVELOPE_ALG),
            "ephemeralPublicKey" to b64(publicDer(ephemeralPublic)),
            "hkdfSalt" to b64(hkdfSalt),
            "nonce" to b64(nonce),
            "tag" to b64(sealed.tag),
            "ciphertext" to b64(sealed.ciphertext),
        )
    }

    fun openEnvelopePayload(keyId: String, readKey: X25519PrivateKeyParameters, raw: Map<String, Any?>): ByteArray {
        try {
            val ephemeralDer = fromB64(raw["ephemeralPublicKey"], "ephemeralPublicKey", DataLockErrorCode.TAMPERED_ENVELOPE)
            val ephemeralInfo = SubjectPublicKeyInfo.getInstance(ephemeralDer)
            val ephemeralPublic = X25519PublicKeyParameters(ephemeralInfo.publicKeyData.bytes, 0)
            val sharedSecret = exchange(readKey, ephemeralPublic)
            val contentKey = hkdf(
                sharedSecret,
                fromB64(raw["hkdfSalt"], "hkdfSalt", DataLockErrorCode.TAMPERED_ENVELOPE),
                "$ENVELOPE_SCHEMA:$keyId".toByteArray(Charsets.UTF_8),
            )
            @Suppress("UNCHECKED_CAST")
            val alg = raw.mapField("alg", DataLockErrorCode.TAMPERED_ENVELOPE) as Map<String, String>
            return aesGcmDecrypt(
                contentKey,
                fromB64(raw["nonce"], "nonce", DataLockErrorCode.TAMPERED_ENVELOPE),
                fromB64(raw["ciphertext"], "ciphertext", DataLockErrorCode.TAMPERED_ENVELOPE),
                fromB64(raw["tag"], "tag", DataLockErrorCode.TAMPERED_ENVELOPE),
                envelopeAad(keyId, alg),
            )
        } catch (ex: DataLockException) {
            throw ex
        } catch (ex: Exception) {
            throw DataLockException(DataLockErrorCode.TAMPERED_ENVELOPE, "Ciphertext authentication failed", ex)
        }
    }

    fun randomBytes(size: Int): ByteArray = ByteArray(size).also { random.nextBytes(it) }

    private fun keyringAad(keyId: String): ByteArray = "$KEYRING_SCHEMA:$keyId:scrypt:AES-256-GCM".toByteArray(Charsets.UTF_8)

    private fun envelopeAad(keyId: String, alg: Map<String, String>): ByteArray =
        "$ENVELOPE_SCHEMA:$keyId:${alg["kem"]}:${alg["kdf"]}:${alg["aead"]}".toByteArray(Charsets.UTF_8)

    private fun exchange(privateKey: X25519PrivateKeyParameters, publicKey: X25519PublicKeyParameters): ByteArray {
        val agreement = X25519Agreement()
        val secret = ByteArray(agreement.agreementSize)
        agreement.init(privateKey)
        agreement.calculateAgreement(publicKey, secret, 0)
        return secret
    }

    private fun hkdf(secret: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
        val generator = HKDFBytesGenerator(SHA256Digest())
        val out = ByteArray(KEY_LENGTH)
        generator.init(HKDFParameters(secret, salt, info))
        generator.generateBytes(out, 0, out.size)
        return out
    }

    private data class Sealed(val ciphertext: ByteArray, val tag: ByteArray)

    private fun aesGcmEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): Sealed {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        val out = cipher.doFinal(plaintext)
        return Sealed(out.copyOfRange(0, out.size - 16), out.copyOfRange(out.size - 16, out.size))
    }

    private fun aesGcmDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, tag: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext + tag)
    }
}

private object SubjectPublicKeyInfoFactory {
    private val x25519Alg = org.bouncycastle.asn1.x509.AlgorithmIdentifier(org.bouncycastle.asn1.edec.EdECObjectIdentifiers.id_X25519)

    fun fromRaw(raw: ByteArray): SubjectPublicKeyInfo = SubjectPublicKeyInfo(x25519Alg, raw)
}

private object PrivateKeyInfoFactory {
    private val x25519Alg = org.bouncycastle.asn1.x509.AlgorithmIdentifier(org.bouncycastle.asn1.edec.EdECObjectIdentifiers.id_X25519)

    fun fromRaw(raw: ByteArray): PrivateKeyInfo = PrivateKeyInfo(x25519Alg, org.bouncycastle.asn1.DEROctetString(raw))
}
