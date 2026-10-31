import io
import json
import os
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hx_datalock import (
    DataEnvelope,
    export_public_key_document,
    generate_attestation_key,
    init_keyring,
    load_keyring,
    sign_envelope,
    verify_attestation,
)
from hx_datalock.stream import lock_stream, open_chunked, open_stream, seal_chunked

PASSWORD = "correct horse battery staple for hx datalock"
ENV = os.environ | {"HXDL_TEST_PASSWORD": PASSWORD, "HXDL_NEW_PASSWORD": "another correct horse battery staple"}
SWIFT = Path(os.environ.get("HXDL_SWIFT_BIN", "sdk/swift/.build/debug/hxdl-swift"))

pytestmark = pytest.mark.skipif(not SWIFT.is_file(), reason="swift codec binary is not built")


def _init(tmp_path: Path) -> tuple[Path, Path, str]:
    keyring_path = tmp_path / "keyring.hxdl.json"
    public_path = tmp_path / "public.hxdl.json"
    init_keyring(keyring_path, PASSWORD, scrypt_n=16384, allow_low_scrypt_n=True)
    export_public_key_document(load_keyring(keyring_path)).write(public_path)
    key_id = json.loads(public_path.read_text(encoding="utf-8"))["publicWriteKey"]["keyId"]
    return keyring_path, public_path, key_id


def test_swift_stream_opens_in_python_and_python_stream_opens_in_swift(tmp_path: Path) -> None:
    keyring_path, public_path, key_id = _init(tmp_path)
    keyring = load_keyring(keyring_path)
    plain = tmp_path / "plain.bin"
    sealed = tmp_path / "sealed.bin"
    payload = b"swift-stream-bytes"
    plain.write_bytes(payload)
    subprocess.run(
        [str(SWIFT), "stream-lock", "--public", str(public_path), "--expect-key-id", key_id, "--in", str(plain), "--out", str(sealed), "--chunk-size", "8"],
        check=True,
    )
    opened = io.BytesIO()
    open_stream(
        key_id=keyring.key_id,
        read_key=keyring.unwrap_read_key(PASSWORD),
        recipient_spki=keyring.public_write_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo),
        src=io.BytesIO(sealed.read_bytes()),
        dst=opened,
    )
    assert opened.getvalue() == payload

    python_sealed = tmp_path / "python.bin"
    with python_sealed.open("wb") as handle:
        lock_stream(
            key_id=keyring.key_id,
            public_key=keyring.public_write_key,
            src=io.BytesIO(b"python-stream"),
            dst=handle,
            chunk_size=4,
        )
    swift_out = tmp_path / "from-python.bin"
    subprocess.run(
        [str(SWIFT), "stream-open", "--keyring", str(keyring_path), "--in", str(python_sealed), "--out", str(swift_out), "--password-env", "HXDL_TEST_PASSWORD"],
        check=True,
        env=ENV,
    )
    assert swift_out.read_bytes() == b"python-stream"


def test_swift_manifest_round_trip_with_python(tmp_path: Path) -> None:
    keyring_path, public_path, _key_id = _init(tmp_path)
    keyring = load_keyring(keyring_path)
    plain = tmp_path / "plain.bin"
    out_dir = tmp_path / "chunks"
    payload = b"manifest-swift-python"
    plain.write_bytes(payload)
    subprocess.run(
        [str(SWIFT), "seal", "--public", str(public_path), "--in", str(plain), "--chunk-size", "8", "--file-id", "file-s", "--out-dir", str(out_dir)],
        check=True,
    )
    manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
    chunks = [(out_dir / f"chunk-{index}.bin").read_bytes() for index in range(len(manifest["chunks"]))]
    opened = io.BytesIO()
    open_chunked(
        key_id=keyring.key_id,
        read_key=keyring.unwrap_read_key(PASSWORD),
        recipient_spki=keyring.public_write_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo),
        manifest=manifest,
        sealed_chunks=chunks,
        dst=opened,
    )
    assert opened.getvalue() == payload

    manifest_path = tmp_path / "py-manifest.json"
    py_dir = tmp_path / "py-chunks"
    py_manifest, py_chunks = seal_chunked(
        key_id=keyring.key_id,
        public_key=keyring.public_write_key,
        src=io.BytesIO(b"python-manifest"),
        chunk_size=6,
        file_id="file-p",
    )
    manifest_path.write_text(json.dumps(py_manifest), encoding="utf-8")
    py_dir.mkdir()
    for index, chunk in enumerate(py_chunks):
        (py_dir / f"chunk-{index}.bin").write_bytes(chunk)
    swift_out = tmp_path / "py-opened.bin"
    subprocess.run(
        [
            str(SWIFT),
            "open-manifest",
            "--keyring",
            str(keyring_path),
            "--manifest",
            str(manifest_path),
            "--chunk-dir",
            str(py_dir),
            "--out",
            str(swift_out),
            "--password-env",
            "HXDL_TEST_PASSWORD",
        ],
        check=True,
        env=ENV,
    )
    assert swift_out.read_bytes() == b"python-manifest"


def test_python_attestation_verifies_in_swift(tmp_path: Path) -> None:
    keyring_path, public_path, key_id = _init(tmp_path)
    keyring = load_keyring(keyring_path)
    envelope_path = tmp_path / "envelope.hxdl.json"
    attestation_path = tmp_path / "attestation.json"
    from hx_datalock import makeSenderDataLock

    envelope = makeSenderDataLock(export_public_key_document(keyring), expected_key_id=key_id).lockText("signed")
    envelope.write(envelope_path)
    private_key, _public = generate_attestation_key()
    attestation = sign_envelope(private_key, envelope, context="path")
    attestation_path.write_text(json.dumps(attestation), encoding="utf-8")
    subprocess.run(
        [str(SWIFT), "verify-attestation", "--envelope", str(envelope_path), "--attestation", str(attestation_path)],
        check=True,
    )
    verify_attestation(attestation, DataEnvelope.read(envelope_path), context="path")
