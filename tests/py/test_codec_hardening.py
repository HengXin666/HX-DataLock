import io
import json

import pytest

from hx_datalock import (
    DataEnvelope,
    DataLockError,
    DataLockErrorCode,
    changed_chunk_indexes,
    check_password_strength,
    create_keyring,
    export_public_key_document,
    generate_attestation_key,
    makeSenderDataLock,
    makeUserDataLock,
    make_user_data_lock,
    open_chunked,
    rewrap_keyring,
    seal_chunked,
    sign_envelope,
    sign_manifest,
    verify_attestation,
    verify_signed_manifest,
)
from hx_datalock.crypto_codec import from_b64


PASSWORD = "correct horse battery staple for hx datalock"


def test_wrong_option_key_is_not_a_password_error() -> None:
    keyring = create_keyring(PASSWORD, scrypt_n=16384, allow_low_scrypt_n=True)
    with pytest.raises(DataLockError) as exc_info:
        makeUserDataLock(keyring, {"master_password": PASSWORD})
    assert exc_info.value.code is DataLockErrorCode.INVALID_ARGUMENT


def test_lock_bytes_accepts_bytearray_and_rejects_str() -> None:
    keyring = create_keyring(PASSWORD, scrypt_n=16384, allow_low_scrypt_n=True)
    user = make_user_data_lock(keyring, PASSWORD)
    envelope = user.lockBytes(bytearray(b"bytes-like"))
    assert user.openBytes(envelope) == b"bytes-like"
    sender = makeSenderDataLock(export_public_key_document(keyring), allow_unpinned_public_key=True)
    with pytest.raises(DataLockError) as exc_info:
        sender.lockBytes("not-bytes")  # type: ignore[arg-type]
    assert exc_info.value.code is DataLockErrorCode.INVALID_ARGUMENT


def test_closed_datalock_has_its_own_code() -> None:
    keyring = create_keyring(PASSWORD, scrypt_n=16384, allow_low_scrypt_n=True)
    with make_user_data_lock(keyring, PASSWORD) as user:
        envelope = user.lockBytes(b"inside")
    with pytest.raises(DataLockError) as exc_info:
        user.openBytes(envelope)
    assert exc_info.value.code is DataLockErrorCode.DATALOCK_CLOSED


def test_parse_and_inspect_do_not_decrypt() -> None:
    keyring = create_keyring(PASSWORD, scrypt_n=16384, allow_low_scrypt_n=True)
    user = make_user_data_lock(keyring, PASSWORD)
    envelope = user.lockText("metadata")
    parsed = DataEnvelope.parse(envelope.serialize())
    info = parsed.inspect()
    assert info["recipientKeyId"] == keyring.key_id
    assert info["ciphertextBytes"] == len(b"metadata")
    assert user.openText(parsed) == "metadata"


def test_open_decodes_ciphertext_once(monkeypatch) -> None:
    keyring = create_keyring(PASSWORD, scrypt_n=16384, allow_low_scrypt_n=True)
    user = make_user_data_lock(keyring, PASSWORD)
    envelope = user.lockBytes(b"x" * 4096)
    calls = {"n": 0}
    original = from_b64

    def counting(*args, **kwargs):
        if args and args[1] == "ciphertext":
            calls["n"] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr("hx_datalock.crypto_codec.from_b64", counting)
    user.openBytes(envelope)
    assert calls["n"] == 1


def test_rewrap_keeps_existing_envelopes_openable() -> None:
    keyring = create_keyring(PASSWORD, scrypt_n=16384, allow_low_scrypt_n=True)
    user = make_user_data_lock(keyring, PASSWORD)
    envelope = user.lockBytes(b"still mine")
    new_password = f"{PASSWORD} rotated"
    rewrapped = rewrap_keyring(keyring, PASSWORD, new_password)
    assert rewrapped.key_id == keyring.key_id
    assert make_user_data_lock(rewrapped, new_password).openBytes(envelope) == b"still mine"
    with pytest.raises(DataLockError) as exc_info:
        make_user_data_lock(rewrapped, PASSWORD)
    assert exc_info.value.code is DataLockErrorCode.WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING


def test_rewrap_public_floor_cannot_be_waived() -> None:
    keyring = create_keyring(PASSWORD, scrypt_n=16384, allow_low_scrypt_n=True)
    with pytest.raises(DataLockError) as exc_info:
        rewrap_keyring(
            keyring,
            PASSWORD,
            "password",
            allow_weak=True,
            allow_low_scrypt_n=True,
            public_keyring=True,
        )
    assert exc_info.value.code is DataLockErrorCode.WEAK_MASTER_PASSWORD


def test_public_keyring_requires_high_entropy() -> None:
    report = check_password_strength(PASSWORD)
    assert report["allowedForPublicKeyring"] is True
    with pytest.raises(DataLockError) as exc_info:
        create_keyring("password", scrypt_n=16384, allow_weak=True, allow_low_scrypt_n=True, public_keyring=True)
    assert exc_info.value.code is DataLockErrorCode.WEAK_MASTER_PASSWORD


def test_invalid_scrypt_n_uses_stable_code() -> None:
    with pytest.raises(DataLockError) as exc_info:
        create_keyring(PASSWORD, scrypt_n=1000)
    assert exc_info.value.code is DataLockErrorCode.INVALID_SCRYPT_PARAMS


def test_stream_round_trip_and_rejects_truncation_and_reorder() -> None:
    keyring = create_keyring(PASSWORD, scrypt_n=16384, allow_low_scrypt_n=True)
    sender = makeSenderDataLock(export_public_key_document(keyring), allow_unpinned_public_key=True)
    user = make_user_data_lock(keyring, PASSWORD)
    payload = b"abcdefghij" * 50
    sealed = io.BytesIO()
    info = sender.lockStream(io.BytesIO(payload), sealed, chunk_size=64)
    assert info["plaintextLength"] == len(payload)
    opened = io.BytesIO()
    user.openStream(io.BytesIO(sealed.getvalue()), opened)
    assert opened.getvalue() == payload

    raw = sealed.getvalue()
    with pytest.raises(DataLockError) as truncated:
        user.openStream(io.BytesIO(raw[:-20]), io.BytesIO())
    assert truncated.value.code is DataLockErrorCode.TAMPERED_STREAM

    header_len = int.from_bytes(raw[5:9], "big")
    offset = 9 + header_len
    spans: list[tuple[int, int]] = []
    while offset < len(raw):
        body_len = int.from_bytes(raw[offset + 1 : offset + 5], "big")
        nxt = offset + 5 + body_len
        spans.append((offset, nxt))
        offset = nxt
    assert len(spans) >= 2
    first, second = spans[0], spans[1]
    reordered_bytes = raw[: first[0]] + raw[second[0] : second[1]] + raw[first[0] : first[1]] + raw[second[1] :]
    with pytest.raises(DataLockError) as reordered:
        user.openStream(io.BytesIO(reordered_bytes), io.BytesIO())
    assert reordered.value.code is DataLockErrorCode.TAMPERED_STREAM


def test_manifest_incremental_reports_only_changed_chunks() -> None:
    keyring = create_keyring(PASSWORD, scrypt_n=16384, allow_low_scrypt_n=True)
    public = keyring.public_write_key
    key_id = keyring.key_id
    first, chunks_a = seal_chunked(
        key_id=key_id,
        public_key=public,
        src=io.BytesIO(b"a" * 100 + b"b" * 100),
        chunk_size=100,
        file_id="file-1",
        version=1,
    )
    second, chunks_b = seal_chunked(
        key_id=key_id,
        public_key=public,
        src=io.BytesIO(b"a" * 100 + b"c" * 100),
        chunk_size=100,
        file_id="file-1",
        version=2,
    )
    assert changed_chunk_indexes(first, second) == [1]
    assert chunks_a[0] != chunks_b[1]
    user = make_user_data_lock(keyring, PASSWORD)
    from cryptography.hazmat.primitives import serialization

    spki = public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    opened = io.BytesIO()
    open_chunked(
        key_id=key_id,
        read_key=user._read_key,
        recipient_spki=spki,
        manifest=second,
        sealed_chunks=chunks_b,
        dst=opened,
    )
    assert opened.getvalue() == b"a" * 100 + b"c" * 100


def test_ed25519_attestation_and_signed_manifest() -> None:
    keyring = create_keyring(PASSWORD, scrypt_n=16384, allow_low_scrypt_n=True)
    user = make_user_data_lock(keyring, PASSWORD)
    envelope = user.lockBytes(b"signed")
    private_key, _public = generate_attestation_key()
    attestation = sign_envelope(private_key, envelope, context="objects/note")
    verify_attestation(attestation, envelope, context="objects/note")
    with pytest.raises(DataLockError) as moved:
        verify_attestation(attestation, envelope, context="objects/other")
    assert moved.value.code is DataLockErrorCode.INVALID_ATTESTATION

    other = user.lockBytes(b"other")
    with pytest.raises(DataLockError):
        verify_attestation(attestation, other, context="objects/note")

    payload = {"schema": "hxdl.compatibilityManifest.v1", "note": "public"}
    signed = sign_manifest(private_key, payload, issuer="hx-datalock")
    assert verify_signed_manifest(signed) == payload
    assert signed["schema"] == "hxdl.signedManifest.v2"
    assert json.loads(json.dumps(attestation))["signer"]["alg"] == "Ed25519"
