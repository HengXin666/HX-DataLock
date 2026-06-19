import json
from pathlib import Path

import pytest

from hx_datalock import (
    DataEnvelope,
    DataLockError,
    DataLockErrorCode,
    Keyring,
    check_password_strength,
    create_keyring,
    decrypt_message,
    encrypt_message,
    export_public_key_document,
    makeSenderDataLock,
    make_v1_compatibility_manifest,
    load_keyring,
    PublicKeyDocument,
)


PASSWORD = "correct horse battery staple for hx datalock"


def test_password_strength_report_warns_but_does_not_block_weak_passwords() -> None:
    weak_report = check_password_strength("password")
    assert weak_report["allowed"] is True
    assert weak_report["level"] == "weak"
    assert weak_report["warnings"]
    assert weak_report["suggestions"]

    strong_report = check_password_strength("correct horse battery staple for hx datalock")
    assert strong_report["allowed"] is True
    assert strong_report["level"] in {"good", "strong"}
    assert strong_report["warnings"] == []

    keyring = create_keyring("password", scrypt_n=16384)
    assert keyring.raw["schema"] == "hxdl.keyring.v1"


def test_master_password_uses_nfc_normalization_for_unlock() -> None:
    decomposed_password = "Cafe\u0301 passphrase for hx datalock"
    composed_password = "Caf\u00e9 passphrase for hx datalock"

    keyring = create_keyring(decomposed_password, scrypt_n=16384)
    envelope = encrypt_message(keyring, b"nfc unlock")

    assert decrypt_message(keyring, composed_password, envelope) == b"nfc unlock"


def test_malformed_keyrings_and_public_key_documents_use_stable_error_codes() -> None:
    keyring = create_keyring(PASSWORD, scrypt_n=16384)
    public_key_document = export_public_key_document(keyring)

    with pytest.raises(DataLockError) as keyring_exc:
        Keyring(
            {
                **keyring.raw,
                "encryptedReadKey": {
                    **keyring.raw["encryptedReadKey"],
                    "kdf": {**keyring.raw["encryptedReadKey"]["kdf"], "salt": "not base64"},
                },
            }
        ).unwrap_read_key(PASSWORD)
    assert keyring_exc.value.code is DataLockErrorCode.INVALID_KEYRING

    with pytest.raises(DataLockError) as public_key_exc:
        PublicKeyDocument(
            {
                **public_key_document.raw,
                "publicWriteKey": {
                    **public_key_document.raw["publicWriteKey"],
                    "spki": "not base64",
                },
            }
        ).verify()
    assert public_key_exc.value.code is DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT


def test_malformed_data_envelope_uses_tampered_envelope_error_code() -> None:
    keyring = create_keyring(PASSWORD, scrypt_n=16384)
    envelope = encrypt_message(keyring, b"malformed envelope")

    with pytest.raises(DataLockError) as envelope_exc:
        decrypt_message(
            keyring,
            PASSWORD,
            DataEnvelope({**envelope.raw, "hkdfSalt": "not base64"}),
        )
    assert envelope_exc.value.code is DataLockErrorCode.TAMPERED_ENVELOPE


def test_v1_documents_write_stable_json_and_read_by_field(tmp_path: Path) -> None:
    keyring_path = tmp_path / "keyring.hxdl.json"
    public_key_path = tmp_path / "public-key.hxdl.json"
    envelope_path = tmp_path / "sealed.hxdl.json"

    keyring = create_keyring(PASSWORD, scrypt_n=16384)
    public_key_document = export_public_key_document(keyring)
    envelope = encrypt_message(keyring, b"stable json foundation")

    keyring.write(keyring_path)
    public_key_document.write(public_key_path)
    envelope.write(envelope_path)

    keyring_bytes = keyring_path.read_bytes()
    public_key_bytes = public_key_path.read_bytes()
    envelope_bytes = envelope_path.read_bytes()
    assert keyring_bytes.endswith(b"\n")
    assert public_key_bytes.endswith(b"\n")
    assert envelope_bytes.endswith(b"\n")
    assert b"\n  \"createdAt\"" in keyring_bytes
    assert b"\n  \"publicWriteKey\"" in public_key_bytes
    assert b"\n  \"recipientKeyId\"" in envelope_bytes
    assert list(json.loads(keyring_bytes).keys()) == [
        "schema",
        "createdAt",
        "publicWriteKey",
        "encryptedReadKey",
    ]
    assert list(json.loads(public_key_bytes).keys()) == [
        "schema",
        "createdAt",
        "publicWriteKey",
    ]
    assert "encryptedReadKey" not in json.loads(public_key_bytes)
    assert list(json.loads(envelope_bytes).keys()) == [
        "schema",
        "createdAt",
        "recipientKeyId",
        "alg",
        "ephemeralPublicKey",
        "hkdfSalt",
        "nonce",
        "tag",
        "ciphertext",
    ]

    unordered_keyring = {
        "encryptedReadKey": keyring.raw["encryptedReadKey"],
        "publicWriteKey": keyring.raw["publicWriteKey"],
        "createdAt": keyring.raw["createdAt"],
        "schema": keyring.raw["schema"],
    }
    keyring_path.write_text(json.dumps(unordered_keyring), encoding="utf-8")
    public_key_path.write_text(
        json.dumps(
            {
                "publicWriteKey": public_key_document.raw["publicWriteKey"],
                "createdAt": public_key_document.raw["createdAt"],
                "schema": public_key_document.raw["schema"],
            }
        ),
        encoding="utf-8",
    )

    unordered_envelope = {
        "ciphertext": envelope.raw["ciphertext"],
        "tag": envelope.raw["tag"],
        "nonce": envelope.raw["nonce"],
        "hkdfSalt": envelope.raw["hkdfSalt"],
        "ephemeralPublicKey": envelope.raw["ephemeralPublicKey"],
        "alg": envelope.raw["alg"],
        "recipientKeyId": envelope.raw["recipientKeyId"],
        "createdAt": envelope.raw["createdAt"],
        "schema": envelope.raw["schema"],
    }
    envelope_path.write_text(json.dumps(unordered_envelope), encoding="utf-8")

    assert PublicKeyDocument.read(public_key_path).key_id == keyring.key_id
    assert decrypt_message(
        load_keyring(keyring_path),
        PASSWORD,
        DataEnvelope.read(envelope_path),
    ) == b"stable json foundation"


@pytest.mark.parametrize(
    ("operation", "expected_code"),
    [
        (
            lambda keyring, envelope: Keyring({**keyring.raw, "schema": "hxdl.keyring.v2"}).verify(),
            DataLockErrorCode.UNSUPPORTED_SCHEMA,
        ),
        (
            lambda keyring, envelope: Keyring(
                {
                    **keyring.raw,
                    "publicWriteKey": {**keyring.raw["publicWriteKey"], "alg": "P-256"},
                }
            ).verify(),
            DataLockErrorCode.UNSUPPORTED_ALGORITHM,
        ),
        (
            lambda keyring, envelope: decrypt_message(
                keyring,
                PASSWORD,
                DataEnvelope({**envelope.raw, "schema": "hxdl.envelope.v2"}),
            ),
            DataLockErrorCode.UNSUPPORTED_SCHEMA,
        ),
        (
            lambda keyring, envelope: decrypt_message(
                keyring,
                PASSWORD,
                DataEnvelope(
                    {
                        **envelope.raw,
                        "alg": {**envelope.raw["alg"], "aead": "ChaCha20-Poly1305"},
                    }
                ),
            ),
            DataLockErrorCode.UNSUPPORTED_ALGORITHM,
        ),
    ],
)
def test_v1_expected_failures_have_stable_error_codes(operation, expected_code) -> None:
    keyring = create_keyring(PASSWORD, scrypt_n=16384)
    envelope = encrypt_message(keyring, b"stable error codes")

    with pytest.raises(DataLockError) as exc_info:
        operation(keyring, envelope)

    assert exc_info.value.code is expected_code


def test_v1_compatibility_fixture_manifest_describes_cross_language_cases() -> None:
    manifest = make_v1_compatibility_manifest()

    assert manifest["schema"] == "hxdl.compatibilityManifest.v1"
    cases = manifest["cases"]
    assert {
        "keyring",
        "publicKeyDocument",
        "dataEnvelope",
        "failureModes",
    } <= {case["kind"] for case in cases}

    for case in cases:
        assert case["id"]
        assert case["producer"] in {"python", "typescript", "android-kotlin", "fixture"}
        assert case["consumers"]
        for document in case.get("documents", []):
            assert document["schema"].startswith("hxdl.")
        if case["kind"] == "failureModes":
            assert {
                DataLockErrorCode.WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING,
                DataLockErrorCode.ENVELOPE_RECIPIENT_MISMATCH,
                DataLockErrorCode.TAMPERED_ENVELOPE,
                DataLockErrorCode.UNSUPPORTED_SCHEMA,
                DataLockErrorCode.UNSUPPORTED_ALGORITHM,
            } <= {DataLockErrorCode(item["expectedCode"]) for item in case["expectations"]}


def test_sender_datalock_locks_bytes_from_public_key_document_only() -> None:
    keyring = create_keyring(PASSWORD, scrypt_n=16384)
    public_key_document = export_public_key_document(keyring)

    sender = makeSenderDataLock(public_key_document)
    envelope = sender.lockBytes(b"write-only sender payload")

    assert envelope.raw["schema"] == "hxdl.envelope.v1"
    assert envelope.raw["recipientKeyId"] == keyring.key_id
    assert decrypt_message(keyring, PASSWORD, envelope) == b"write-only sender payload"
    assert not hasattr(sender, "openBytes")
    assert not hasattr(sender, "unwrap_read_key")


def test_sender_datalock_envelope_aad_does_not_bind_creation_time() -> None:
    keyring = create_keyring(PASSWORD, scrypt_n=16384)
    sender = makeSenderDataLock(export_public_key_document(keyring))

    envelope = sender.lockBytes(b"creation time is display metadata")
    envelope_with_changed_creation_time = DataEnvelope(
        {
            **envelope.raw,
            "createdAt": "2000-01-01T00:00:00.000Z",
        }
    )

    assert (
        decrypt_message(keyring, PASSWORD, envelope_with_changed_creation_time)
        == b"creation time is display metadata"
    )


def test_sender_datalock_rejects_keyrings_and_invalid_public_key_documents() -> None:
    keyring = create_keyring(PASSWORD, scrypt_n=16384)
    public_key_document = export_public_key_document(keyring)

    with pytest.raises(DataLockError) as keyring_exc:
        makeSenderDataLock(keyring)
    assert keyring_exc.value.code is DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT

    with pytest.raises(DataLockError) as public_doc_exc:
        makeSenderDataLock(
            PublicKeyDocument(
                {
                    **public_key_document.raw,
                    "encryptedReadKey": keyring.raw["encryptedReadKey"],
                }
            )
        )
    assert public_doc_exc.value.code is DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT


def test_sender_datalock_lock_text_uses_strict_utf8() -> None:
    keyring = create_keyring(PASSWORD, scrypt_n=16384)
    sender = makeSenderDataLock(export_public_key_document(keyring))

    envelope = sender.lockText("HX DataLock 文本")
    assert decrypt_message(keyring, PASSWORD, envelope) == "HX DataLock 文本".encode("utf-8")

    with pytest.raises(DataLockError) as exc_info:
        sender.lockText("bad surrogate \ud800")
    assert exc_info.value.code is DataLockErrorCode.INVALID_UTF8


def test_sender_datalock_lock_file_writes_envelope_and_enforces_v1_limit(tmp_path: Path) -> None:
    keyring = create_keyring(PASSWORD, scrypt_n=16384)
    sender = makeSenderDataLock(export_public_key_document(keyring))
    input_path = tmp_path / "payload.bin"
    envelope_path = tmp_path / "payload.hxdl.json"

    input_path.write_bytes(b"sender file payload")
    envelope = sender.lockFile(input_path, envelope_path)

    assert decrypt_message(keyring, PASSWORD, envelope) == b"sender file payload"
    assert decrypt_message(keyring, PASSWORD, DataEnvelope.read(envelope_path)) == b"sender file payload"

    oversized_path = tmp_path / "oversized.bin"
    with oversized_path.open("wb") as oversized_file:
        oversized_file.truncate(25 * 1024 * 1024 + 1)
    with pytest.raises(DataLockError) as exc_info:
        sender.lockFile(oversized_path, tmp_path / "oversized.hxdl.json")
    assert exc_info.value.code is DataLockErrorCode.OVERSIZED_FILE
