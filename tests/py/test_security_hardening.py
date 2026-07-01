from __future__ import annotations

import copy
import os
import stat

import pytest

from hx_datalock import (
    DataEnvelope,
    DataLockError,
    DataLockErrorCode,
    Keyring,
    create_keyring,
    export_public_key_document,
    makeSenderDataLock,
    send_file,
    send_file_with_public_doc,
)
from hx_datalock.constants import MAX_V1_FILE_BYTES


MASTER_PASSWORD = "correct horse battery staple 2026 HX-DataLock hardening"


def test_sender_file_helper_accepts_public_key_document(tmp_path):
    keyring = create_keyring(MASTER_PASSWORD)
    public_document = export_public_key_document(keyring)

    public_path = tmp_path / "public.hxdl.json"
    input_path = tmp_path / "message.txt"
    output_path = tmp_path / "message.hxdl.json"

    public_document.write(public_path)
    input_path.write_text("hello", encoding="utf-8")

    envelope = send_file_with_public_doc(public_path, input_path, output_path)
    assert envelope.raw["recipientKeyId"] == public_document.key_id


def test_sender_datalock_rejects_full_keyring():
    keyring = create_keyring(MASTER_PASSWORD)

    with pytest.raises(DataLockError) as exc_info:
        makeSenderDataLock(keyring)
    assert exc_info.value.code == DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT


def test_legacy_send_file_keeps_v1_keyring_compatibility(tmp_path):
    keyring = create_keyring(MASTER_PASSWORD)
    keyring_path = tmp_path / "keyring.hxdl.json"
    input_path = tmp_path / "message.txt"
    output_path = tmp_path / "message.hxdl.json"

    keyring.write(keyring_path)
    input_path.write_text("hello", encoding="utf-8")

    envelope = send_file(keyring_path, input_path, output_path)
    assert envelope.raw["recipientKeyId"] == keyring.key_id


@pytest.mark.skipif(os.name != "posix", reason="POSIX file mode assertions require a POSIX platform")
def test_keyring_write_converges_to_owner_read_write_permissions(tmp_path):
    keyring = create_keyring(MASTER_PASSWORD)
    keyring_path = tmp_path / "keyring.hxdl.json"
    keyring_path.write_text("{}", encoding="utf-8")
    keyring_path.chmod(0o644)

    keyring.write(keyring_path)

    mode = stat.S_IMODE(keyring_path.stat().st_mode)
    assert mode == 0o600


def test_keyring_verify_rejects_oversized_scrypt_n():
    keyring = create_keyring(MASTER_PASSWORD)
    raw = copy.deepcopy(keyring.raw)
    raw["encryptedReadKey"]["kdf"]["N"] = 2**30

    with pytest.raises(DataLockError) as exc_info:
        Keyring(raw).verify()
    assert exc_info.value.code == DataLockErrorCode.INVALID_KEYRING


def test_envelope_verify_rejects_oversized_ciphertext_without_decode():
    keyring = create_keyring(MASTER_PASSWORD)
    public_document = export_public_key_document(keyring)
    envelope = makeSenderDataLock(public_document).lockBytes(b"hello")
    raw = copy.deepcopy(envelope.raw)
    max_b64_chars = ((MAX_V1_FILE_BYTES + 2) // 3) * 4
    raw["ciphertext"] = "A" * (max_b64_chars + 4)

    with pytest.raises(DataLockError) as exc_info:
        DataEnvelope(raw).verify()
    assert exc_info.value.code == DataLockErrorCode.OVERSIZED_FILE
