from __future__ import annotations

import copy

import pytest

from hx_datalock import (
    DataEnvelope,
    DataLockError,
    DataLockErrorCode,
    Keyring,
    create_keyring,
    export_public_key_document,
    send_file,
    send_file_with_public_doc,
)
from hx_datalock.constants import MAX_V1_FILE_BYTES


MASTER_PASSWORD = "correct horse battery staple 2026 HX-DataLock hardening"


def test_sender_file_helper_requires_public_key_document(tmp_path):
    keyring = create_keyring(MASTER_PASSWORD)
    public_document = export_public_key_document(keyring)

    keyring_path = tmp_path / "keyring.hxdl.json"
    public_path = tmp_path / "public.hxdl.json"
    input_path = tmp_path / "message.txt"
    output_path = tmp_path / "message.hxdl.json"

    keyring.write(keyring_path)
    public_document.write(public_path)
    input_path.write_text("hello", encoding="utf-8")

    envelope = send_file_with_public_doc(public_path, input_path, output_path)
    assert envelope.raw["recipientKeyId"] == public_document.key_id

    with pytest.raises(DataLockError) as exc_info:
        send_file(keyring_path, input_path, output_path)
    assert exc_info.value.code == DataLockErrorCode.UNSUPPORTED_SCHEMA


def test_keyring_verify_rejects_oversized_scrypt_n():
    keyring = create_keyring(MASTER_PASSWORD)
    raw = copy.deepcopy(keyring.raw)
    raw["encryptedReadKey"]["kdf"]["N"] = 2**30

    with pytest.raises(DataLockError) as exc_info:
        Keyring(raw).verify()
    assert exc_info.value.code == DataLockErrorCode.INVALID_KEYRING


def test_envelope_verify_rejects_oversized_ciphertext_without_decode():
    keyring = create_keyring(MASTER_PASSWORD)
    envelope = send_file_with_public_doc_from_document(keyring, b"hello")
    raw = copy.deepcopy(envelope.raw)
    max_b64_chars = ((MAX_V1_FILE_BYTES + 2) // 3) * 4
    raw["ciphertext"] = "A" * (max_b64_chars + 4)

    with pytest.raises(DataLockError) as exc_info:
        DataEnvelope(raw).verify()
    assert exc_info.value.code == DataLockErrorCode.TAMPERED_ENVELOPE


def send_file_with_public_doc_from_document(keyring, payload: bytes) -> DataEnvelope:
    public_document = export_public_key_document(keyring)
    sender = __import__("hx_datalock").makeSenderDataLock(public_document)
    return sender.lockBytes(payload)
