"""hxdl.stream.v1 and hxdl.manifest.v1.

A stream is one binary container. Each chunk is AES-256-GCM under a single
content key. The nonce and AAD bind the chunk index and a last-chunk flag, so
reordering, truncation, and appending fail authentication.

A manifest lists independent one-chunk streams for incremental upload. Only
chunks whose sealed hash changed need to be sent again. fileId and chunkIndex
live in that chunk's header, so a chunk cannot be moved to another file.
Manifest version is outside the chunk AAD: unchanged chunks stay valid when
the version increases. Rollback of the manifest itself is an application
concern; sign the manifest with an Envelope Attestation signer if you need to
detect it.
"""

from __future__ import annotations

import hashlib
import io
import json
import secrets
from typing import Any, BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .constants import (
    DEFAULT_STREAM_CHUNK_SIZE,
    ENVELOPE_ALG,
    KEY_LENGTH,
    MANIFEST_SCHEMA,
    MAX_STREAM_CHUNK_SIZE,
    MAX_STREAM_HEADER_BYTES,
    MIN_STREAM_CHUNK_SIZE,
    STREAM_MAGIC,
    STREAM_SCHEMA,
    STREAM_VERSION,
)
from .crypto_codec import b64, sha256_base64url
from .errors import DataLockError, DataLockErrorCode


def _require_chunk_size(chunk_size: int) -> int:
    if (
        not isinstance(chunk_size, int)
        or isinstance(chunk_size, bool)
        or chunk_size < MIN_STREAM_CHUNK_SIZE
        or chunk_size > MAX_STREAM_CHUNK_SIZE
    ):
        raise DataLockError(
            DataLockErrorCode.INVALID_ARGUMENT,
            f"chunk_size must be an integer from {MIN_STREAM_CHUNK_SIZE} to {MAX_STREAM_CHUNK_SIZE}",
        )
    return chunk_size


def stream_nonce(index: int, is_last: bool) -> bytes:
    if index < 0 or index >= 2**64:
        raise DataLockError(DataLockErrorCode.INVALID_ARGUMENT, "stream chunk index is out of range")
    return index.to_bytes(8, "big") + b"\x00\x00\x00" + (b"\x01" if is_last else b"\x00")


def stream_aad(key_id: str, chunk_size: int, index: int, is_last: bool, header_sha256: str) -> bytes:
    flag = "1" if is_last else "0"
    return (
        f"{STREAM_SCHEMA}:{key_id}:X25519:HKDF-SHA256:AES-256-GCM:"
        f"{chunk_size}:{index}:{flag}:{header_sha256}"
    ).encode("utf-8")


def _header_bytes(header: dict[str, Any]) -> bytes:
    encoded = json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_STREAM_HEADER_BYTES:
        raise DataLockError(DataLockErrorCode.INVALID_ARGUMENT, "stream header is too large")
    return encoded


def _content_key(shared_secret: bytes, hkdf_salt: bytes, key_id: str, recipient_spki: bytes) -> bytes:
    info = b"hxdl.stream.v1:" + key_id.encode("utf-8") + b":" + hashlib.sha256(recipient_spki).digest()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=hkdf_salt,
        info=info,
    ).derive(shared_secret)


def lock_stream(
    *,
    key_id: str,
    public_key: x25519.X25519PublicKey,
    src: BinaryIO,
    dst: BinaryIO,
    chunk_size: int = DEFAULT_STREAM_CHUNK_SIZE,
    file_id: str | None = None,
    chunk_index: int | None = None,
) -> dict[str, Any]:
    """Encrypt src into a hxdl.stream.v1 container written to dst."""
    chunk_size = _require_chunk_size(chunk_size)
    if file_id is not None and (not isinstance(file_id, str) or not file_id or "\n" in file_id):
        raise DataLockError(DataLockErrorCode.INVALID_ARGUMENT, "file_id must be a single-line string")
    if chunk_index is not None and (not isinstance(chunk_index, int) or isinstance(chunk_index, bool) or chunk_index < 0):
        raise DataLockError(DataLockErrorCode.INVALID_ARGUMENT, "chunk_index must be a non-negative integer")

    recipient_spki = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    ephemeral = x25519.X25519PrivateKey.generate()
    ephemeral_spki = ephemeral.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    shared = ephemeral.exchange(public_key)
    hkdf_salt = secrets.token_bytes(32)
    content_key = _content_key(shared, hkdf_salt, key_id, recipient_spki)
    header: dict[str, Any] = {
        "schema": STREAM_SCHEMA,
        "recipientKeyId": key_id,
        "alg": dict(ENVELOPE_ALG),
        "ephemeralPublicKey": b64(ephemeral_spki),
        "hkdfSalt": b64(hkdf_salt),
        "chunkSize": chunk_size,
    }
    if file_id is not None:
        header["fileId"] = file_id
    if chunk_index is not None:
        header["chunkIndex"] = chunk_index
    header_bytes = _header_bytes(header)
    header_hash = sha256_base64url(header_bytes)
    _write_all(dst, STREAM_MAGIC)
    _write_all(dst, bytes([STREAM_VERSION]))
    _write_all(dst, len(header_bytes).to_bytes(4, "big"))
    _write_all(dst, header_bytes)

    index = 0
    total = 0
    for plaintext, is_last in _iter_chunks(src, chunk_size):
        _write_chunk(dst, content_key, key_id, chunk_size, index, is_last, header_hash, plaintext)
        total += len(plaintext)
        index += 1

    return {
        "schema": STREAM_SCHEMA,
        "recipientKeyId": key_id,
        "chunkSize": chunk_size,
        "chunkCount": index,
        "plaintextLength": total,
        "fileId": file_id,
        "chunkIndex": chunk_index,
    }


def _iter_chunks(src: BinaryIO, chunk_size: int):
    """Yield (plaintext, is_last). A short read is accumulated until EOF or chunk_size."""
    previous, eof = _read_up_to(src, chunk_size)
    if eof:
        yield previous, True
        return
    while True:
        nxt, nxt_eof = _read_up_to(src, chunk_size)
        if nxt_eof and nxt == b"":
            yield previous, True
            return
        yield previous, False
        previous = nxt
        if nxt_eof:
            yield previous, True
            return


def _read_up_to(src: BinaryIO, size: int) -> tuple[bytes, bool]:
    """Read until `size` bytes or real EOF. A short read is not treated as EOF."""
    buf = bytearray()
    while len(buf) < size:
        block = src.read(size - len(buf))
        if block is None or not isinstance(block, (bytes, bytearray)):
            raise DataLockError(DataLockErrorCode.INVALID_ARGUMENT, "stream source must yield bytes")
        if block == b"":
            return bytes(buf), True
        buf.extend(block)
    return bytes(buf), False


def _read_chunk(src: BinaryIO, chunk_size: int) -> bytes:
    data, _eof = _read_up_to(src, chunk_size)
    return data


def _write_all(dst: BinaryIO, payload: bytes) -> None:
    view = memoryview(payload)
    while len(view):
        written = dst.write(view)
        if written is None:
            return
        if written <= 0:
            raise DataLockError(DataLockErrorCode.INVALID_ARGUMENT, "stream destination accepted no bytes")
        view = view[written:]


def _write_chunk(
    dst: BinaryIO,
    content_key: bytes,
    key_id: str,
    chunk_size: int,
    index: int,
    is_last: bool,
    header_hash: str,
    plaintext: bytes,
) -> None:
    sealed = AESGCM(content_key).encrypt(
        stream_nonce(index, is_last),
        plaintext,
        stream_aad(key_id, chunk_size, index, is_last, header_hash),
    )
    _write_all(dst, b"\x01" if is_last else b"\x00")
    _write_all(dst, len(sealed).to_bytes(4, "big"))
    _write_all(dst, sealed)


def open_stream(
    *,
    key_id: str,
    read_key: x25519.X25519PrivateKey,
    recipient_spki: bytes,
    src: BinaryIO,
    dst: BinaryIO,
) -> dict[str, Any]:
    """Decrypt a hxdl.stream.v1 container. v1 Data Envelopes are not this format."""
    magic = _read_exact(src, 4, "stream magic")
    if magic != STREAM_MAGIC:
        raise DataLockError(DataLockErrorCode.TAMPERED_STREAM, "stream magic does not match hxdl.stream.v1")
    version = _read_exact(src, 1, "stream version")
    if version != bytes([STREAM_VERSION]):
        raise DataLockError(DataLockErrorCode.UNSUPPORTED_SCHEMA, "Unsupported stream version")
    header_len_raw = _read_exact(src, 4, "stream header length")
    header_len = int.from_bytes(header_len_raw, "big")
    if header_len == 0 or header_len > MAX_STREAM_HEADER_BYTES:
        raise DataLockError(DataLockErrorCode.TAMPERED_STREAM, "stream header length is invalid")
    header_bytes = _read_exact(src, header_len, "stream header")
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DataLockError(DataLockErrorCode.TAMPERED_STREAM, "stream header is not JSON") from exc
    if not isinstance(header, dict) or header.get("schema") != STREAM_SCHEMA:
        raise DataLockError(DataLockErrorCode.UNSUPPORTED_SCHEMA, "Unsupported stream schema")
    if header.get("recipientKeyId") != key_id:
        raise DataLockError(DataLockErrorCode.ENVELOPE_RECIPIENT_MISMATCH, "stream recipient does not match the Keyring")
    if header.get("alg") != ENVELOPE_ALG:
        raise DataLockError(DataLockErrorCode.UNSUPPORTED_ALGORITHM, "stream must use X25519, HKDF-SHA256, and AES-256-GCM")
    chunk_size = header.get("chunkSize")
    if not isinstance(chunk_size, int) or isinstance(chunk_size, bool):
        raise DataLockError(DataLockErrorCode.TAMPERED_STREAM, "stream chunkSize is invalid")
    _require_chunk_size(chunk_size)
    from .crypto_codec import from_b64

    ephemeral_spki = from_b64(
        header.get("ephemeralPublicKey"),
        "ephemeralPublicKey",
        error_code=DataLockErrorCode.TAMPERED_STREAM,
        max_length=512,
    )
    hkdf_salt = from_b64(
        header.get("hkdfSalt"),
        "hkdfSalt",
        error_code=DataLockErrorCode.TAMPERED_STREAM,
        exact_length=32,
    )
    try:
        ephemeral_public = serialization.load_der_public_key(ephemeral_spki)
    except Exception as exc:
        raise DataLockError(DataLockErrorCode.TAMPERED_STREAM, "Invalid stream ephemeral public key") from exc
    if not isinstance(ephemeral_public, x25519.X25519PublicKey):
        raise DataLockError(DataLockErrorCode.UNSUPPORTED_ALGORITHM, "stream ephemeral key is not X25519")
    try:
        shared = read_key.exchange(ephemeral_public)
    except ValueError as exc:
        raise DataLockError(DataLockErrorCode.TAMPERED_STREAM, "Invalid stream ephemeral public key") from exc
    content_key = _content_key(shared, hkdf_salt, key_id, recipient_spki)
    header_hash = sha256_base64url(header_bytes)
    aesgcm = AESGCM(content_key)

    index = 0
    total = 0
    saw_last = False
    while True:
        flag = src.read(1)
        if flag == b"":
            break
        if saw_last:
            raise DataLockError(DataLockErrorCode.TAMPERED_STREAM, "stream continues after the last chunk")
        if flag not in (b"\x00", b"\x01"):
            raise DataLockError(DataLockErrorCode.TAMPERED_STREAM, "stream chunk flag is invalid")
        is_last = flag == b"\x01"
        body_len = int.from_bytes(_read_exact(src, 4, "chunk length"), "big")
        if body_len < 16 or body_len > chunk_size + 16:
            raise DataLockError(DataLockErrorCode.TAMPERED_STREAM, "stream chunk length is invalid")
        body = _read_exact(src, body_len, "chunk body")
        try:
            plaintext = aesgcm.decrypt(
                stream_nonce(index, is_last),
                body,
                stream_aad(key_id, chunk_size, index, is_last, header_hash),
            )
        except InvalidTag as exc:
            raise DataLockError(DataLockErrorCode.TAMPERED_STREAM, "stream chunk authentication failed") from exc
        if not is_last and len(plaintext) != chunk_size:
            raise DataLockError(DataLockErrorCode.TAMPERED_STREAM, "non-final stream chunk has an unexpected length")
        if is_last and len(plaintext) > chunk_size:
            raise DataLockError(DataLockErrorCode.TAMPERED_STREAM, "final stream chunk exceeds chunkSize")
        _write_all(dst, plaintext)
        total += len(plaintext)
        index += 1
        saw_last = is_last
    if not saw_last:
        raise DataLockError(DataLockErrorCode.TAMPERED_STREAM, "stream ended before the last chunk")
    return {
        "schema": STREAM_SCHEMA,
        "recipientKeyId": key_id,
        "chunkSize": chunk_size,
        "chunkCount": index,
        "plaintextLength": total,
        "fileId": header.get("fileId"),
        "chunkIndex": header.get("chunkIndex"),
    }


def _read_exact(src: BinaryIO, size: int, what: str) -> bytes:
    data, eof = _read_up_to(src, size)
    if eof or len(data) != size:
        raise DataLockError(DataLockErrorCode.TAMPERED_STREAM, f"stream ended inside {what}")
    return data


def seal_chunked(
    *,
    key_id: str,
    public_key: x25519.X25519PublicKey,
    src: BinaryIO,
    chunk_size: int = DEFAULT_STREAM_CHUNK_SIZE,
    file_id: str,
    version: int = 1,
    previous_manifest: dict[str, Any] | None = None,
    previous_sealed: list[bytes] | None = None,
) -> tuple[dict[str, Any], list[bytes]]:
    """Split src into independent sealed chunks plus an hxdl.manifest.v1 document.

    When ``previous_manifest`` and ``previous_sealed`` are passed, a chunk whose
    plaintext hash is unchanged keeps the previous sealed bytes and manifest
    entry. ``changed_chunk_indexes`` then matches the bytes that must be uploaded.
    """
    if not isinstance(file_id, str) or not file_id:
        raise DataLockError(DataLockErrorCode.INVALID_ARGUMENT, "file_id is required")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise DataLockError(DataLockErrorCode.INVALID_ARGUMENT, "manifest version must be a positive integer")
    chunk_size = _require_chunk_size(chunk_size)
    if (previous_manifest is None) ^ (previous_sealed is None):
        raise DataLockError(
            DataLockErrorCode.INVALID_ARGUMENT,
            "previous_manifest and previous_sealed must be passed together",
        )
    previous_by_index: dict[int, tuple[dict[str, Any], bytes]] = {}
    if previous_manifest is not None and previous_sealed is not None:
        _validate_manifest(previous_manifest)
        if previous_manifest["fileId"] != file_id:
            raise DataLockError(DataLockErrorCode.INVALID_MANIFEST, "previous manifest belongs to a different file")
        if len(previous_sealed) != len(previous_manifest["chunks"]):
            raise DataLockError(DataLockErrorCode.INVALID_MANIFEST, "previous sealed chunk count does not match the manifest")
        for entry, sealed in zip(previous_manifest["chunks"], previous_sealed, strict=True):
            if sha256_base64url(sealed) != entry["sealedSha256"]:
                raise DataLockError(DataLockErrorCode.INVALID_MANIFEST, "previous sealed hash does not match the manifest")
            previous_by_index[entry["index"]] = (entry, sealed)
    chunks: list[bytes] = []
    entries: list[dict[str, Any]] = []
    total = 0
    index = 0
    while True:
        block, eof = _read_up_to(src, chunk_size)
        if eof and block == b"" and index > 0:
            break
        digest = sha256_base64url(block)
        reused = previous_by_index.get(index)
        if reused is not None and reused[0]["plaintextSha256"] == digest and reused[0]["plaintextLength"] == len(block):
            sealed = reused[1]
        else:
            sealed_buf = io.BytesIO()
            lock_stream(
                key_id=key_id,
                public_key=public_key,
                src=io.BytesIO(block),
                dst=sealed_buf,
                chunk_size=chunk_size,
                file_id=file_id,
                chunk_index=index,
            )
            sealed = sealed_buf.getvalue()
        entries.append(
            {
                "index": index,
                "plaintextLength": len(block),
                "plaintextSha256": digest,
                "sealedSha256": sha256_base64url(sealed),
            }
        )
        chunks.append(sealed)
        total += len(block)
        index += 1
        if eof or len(block) < chunk_size:
            break
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "fileId": file_id,
        "version": version,
        "chunkSize": chunk_size,
        "totalPlaintextLength": total,
        "chunks": entries,
    }
    return manifest, chunks


def open_chunked(
    *,
    key_id: str,
    read_key: x25519.X25519PrivateKey,
    recipient_spki: bytes,
    manifest: dict[str, Any],
    sealed_chunks: list[bytes],
    dst: BinaryIO,
) -> dict[str, Any]:
    """Open chunks named by a manifest. Order, length, and hashes are checked."""
    _validate_manifest(manifest)
    entries = manifest["chunks"]
    if len(sealed_chunks) != len(entries):
        raise DataLockError(DataLockErrorCode.INVALID_MANIFEST, "sealed chunk count does not match the manifest")
    total = 0
    for entry, sealed in zip(entries, sealed_chunks, strict=True):
        if sha256_base64url(sealed) != entry["sealedSha256"]:
            raise DataLockError(DataLockErrorCode.INVALID_MANIFEST, f"sealed hash mismatch for chunk {entry['index']}")
        opened = io.BytesIO()
        info = open_stream(
            key_id=key_id,
            read_key=read_key,
            recipient_spki=recipient_spki,
            src=io.BytesIO(sealed),
            dst=opened,
        )
        plaintext = opened.getvalue()
        if info.get("fileId") != manifest["fileId"] or info.get("chunkIndex") != entry["index"]:
            raise DataLockError(DataLockErrorCode.INVALID_MANIFEST, f"chunk {entry['index']} is bound to a different file")
        if len(plaintext) != entry["plaintextLength"] or sha256_base64url(plaintext) != entry["plaintextSha256"]:
            raise DataLockError(DataLockErrorCode.TAMPERED_STREAM, f"plaintext hash mismatch for chunk {entry['index']}")
        _write_all(dst, plaintext)
        total += len(plaintext)
    if total != manifest["totalPlaintextLength"]:
        raise DataLockError(DataLockErrorCode.INVALID_MANIFEST, "manifest total length does not match the chunks")
    return {
        "schema": MANIFEST_SCHEMA,
        "fileId": manifest["fileId"],
        "version": manifest["version"],
        "plaintextLength": total,
        "chunkCount": len(entries),
    }


def changed_chunk_indexes(previous: dict[str, Any], current: dict[str, Any]) -> list[int]:
    """Indexes whose plaintext hash changed.

    Unchanged chunks keep their previous sealed bytes when ``seal_chunked`` is
    given the previous manifest. A manifest that is not signed can still drop a
    tail chunk and shrink ``totalPlaintextLength``; that truncation is not
    visible to chunk AEAD. Sign the manifest to detect it.
    """
    _validate_manifest(previous)
    _validate_manifest(current)
    if previous["fileId"] != current["fileId"]:
        raise DataLockError(DataLockErrorCode.INVALID_MANIFEST, "manifests belong to different files")
    previous_plain = {entry["index"]: entry["plaintextSha256"] for entry in previous["chunks"]}
    return [
        entry["index"]
        for entry in current["chunks"]
        if previous_plain.get(entry["index"]) != entry["plaintextSha256"]
    ]


def _validate_manifest(manifest: dict[str, Any]) -> None:
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        raise DataLockError(DataLockErrorCode.INVALID_MANIFEST, "manifest schema must be hxdl.manifest.v1")
    if not isinstance(manifest.get("fileId"), str) or not manifest["fileId"]:
        raise DataLockError(DataLockErrorCode.INVALID_MANIFEST, "manifest fileId is missing")
    if not isinstance(manifest.get("version"), int) or isinstance(manifest["version"], bool) or manifest["version"] < 1:
        raise DataLockError(DataLockErrorCode.INVALID_MANIFEST, "manifest version is invalid")
    chunks = manifest.get("chunks")
    if not isinstance(chunks, list) or not chunks:
        raise DataLockError(DataLockErrorCode.INVALID_MANIFEST, "manifest must list at least one chunk")
    for expected, entry in enumerate(chunks):
        if not isinstance(entry, dict) or entry.get("index") != expected:
            raise DataLockError(DataLockErrorCode.INVALID_MANIFEST, "manifest chunk indexes must be contiguous from 0")
        if not isinstance(entry.get("plaintextLength"), int) or isinstance(entry.get("plaintextLength"), bool):
            raise DataLockError(DataLockErrorCode.INVALID_MANIFEST, "manifest plaintextLength must be an integer")
        for field in ("plaintextSha256", "sealedSha256"):
            if not isinstance(entry.get(field), str) or not entry[field]:
                raise DataLockError(DataLockErrorCode.INVALID_MANIFEST, f"manifest chunk is missing {field}")
