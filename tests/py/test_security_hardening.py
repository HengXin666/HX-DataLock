from __future__ import annotations

import base64
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
    init_keyring,
    makeSenderDataLock,
    makeUserDataLock,
    send_file,
    send_file_with_public_doc,
    verify_public_key_document_key_id,
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


def test_public_key_document_key_id_pinning_rejects_replaced_document():
    trusted = export_public_key_document(create_keyring(MASTER_PASSWORD))
    replaced = export_public_key_document(create_keyring(f"{MASTER_PASSWORD} replacement"))

    with pytest.raises(DataLockError) as exc_info:
        verify_public_key_document_key_id(replaced, trusted.key_id)
    assert exc_info.value.code == DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT

    with pytest.raises(DataLockError) as sender_exc_info:
        makeSenderDataLock(replaced, expected_key_id=trusted.key_id)
    assert sender_exc_info.value.code == DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT


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


def test_password_strength_report_reaches_the_caller(tmp_path):
    """ADR 0012 requires the report before Keyring creation, so it must not be discarded."""
    seen = []
    create_keyring("password", scrypt_n=16384, on_password_report=seen.append)

    assert len(seen) == 1
    assert seen[0]["allowed"] is True
    assert seen[0]["level"] == "weak"
    assert seen[0]["warnings"]

    # A weak password still creates a Keyring in v1; the report only informs.
    assert load_keyring_path_roundtrip(tmp_path, "password") is not None


def load_keyring_path_roundtrip(tmp_path, password):
    from hx_datalock import load_keyring

    path = tmp_path / "roundtrip.hxdl.json"
    init_keyring(path, password, scrypt_n=16384)
    return load_keyring(path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file mode assertions require a POSIX platform")
def test_decrypted_plaintext_is_written_owner_only(tmp_path):
    """A decrypted payload is as sensitive as the Keyring and must not follow umask."""
    from hx_datalock import encrypt_message, init_keyring, load_keyring, open_file

    password = "correct horse battery staple 2026 HX-DataLock hardening"
    keyring_path = tmp_path / "keyring.hxdl.json"
    envelope_path = tmp_path / "message.hxdl.json"
    output_path = tmp_path / "opened.bin"

    init_keyring(keyring_path, password, scrypt_n=16384)
    encrypt_message(load_keyring(keyring_path), b"secret").write(envelope_path)
    open_file(keyring_path, envelope_path, output_path, password)

    assert stat.S_IMODE(output_path.stat().st_mode) == 0o600

    # Pre-existing permissive files converge too, matching Keyring write behaviour.
    output_path.chmod(0o644)
    open_file(keyring_path, envelope_path, output_path, password)
    assert stat.S_IMODE(output_path.stat().st_mode) == 0o600


def test_creation_time_must_be_a_millisecond_timestamp():
    """Creation Time is outside the AAD, so it must at least be well-formed.

    ADR 0015 keeps Creation Time out of the AAD on purpose, which means any
    holder of a document can rewrite it. Leaving the field unvalidated let it be
    a number, an object, null, or a list, so display and any time-based decision
    built on it were trivially forgeable.
    """
    keyring = create_keyring(MASTER_PASSWORD, scrypt_n=16384)
    envelope = makeSenderDataLock(export_public_key_document(keyring)).lockBytes(b"probe")

    for bad in (12345, None, True, ["x"], {"a": 1}, "1999-01-01", "2026-09-27T11:00:00Z"):
        tampered = dict(envelope.raw)
        tampered["createdAt"] = bad
        with pytest.raises(DataLockError) as exc_info:
            DataEnvelope(tampered).verify()
        assert exc_info.value.code == DataLockErrorCode.TAMPERED_ENVELOPE

    # A well-formed timestamp is still accepted, and stays forgeable by design.
    rewritten = dict(envelope.raw)
    rewritten["createdAt"] = "1999-01-01T00:00:00.000Z"
    DataEnvelope(rewritten).verify()

    broken_keyring = copy.deepcopy(keyring.raw)
    broken_keyring["createdAt"] = 12345
    with pytest.raises(DataLockError) as keyring_exc:
        Keyring(broken_keyring).verify()
    assert keyring_exc.value.code == DataLockErrorCode.INVALID_KEYRING


def test_low_order_ephemeral_key_reports_a_stable_error_code():
    """An all-zero ephemeral key must not escape as a raw ValueError.

    X25519 refuses a low-order point, and that refusal used to surface as
    "ValueError: Error computing shared key." in Python and an ERR_OSSL_* error in
    Node, which bypassed the stable error-code contract of ADR 0021 entirely.
    """
    keyring = create_keyring(MASTER_PASSWORD, scrypt_n=16384)
    envelope = makeSenderDataLock(export_public_key_document(keyring)).lockBytes(b"probe")
    user = makeUserDataLock(keyring, {"masterPassword": MASTER_PASSWORD})

    zero_point = base64.b64encode(
        bytes.fromhex("302a300506032b656e032100") + bytes(32)
    ).decode()
    tampered = dict(envelope.raw)
    tampered["ephemeralPublicKey"] = zero_point

    with pytest.raises(DataLockError) as exc_info:
        user.openBytes(DataEnvelope(tampered))
    assert exc_info.value.code == DataLockErrorCode.TAMPERED_ENVELOPE


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
