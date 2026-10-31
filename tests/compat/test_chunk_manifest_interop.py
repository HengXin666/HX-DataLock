import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hx_datalock import load_keyring, open_chunked, seal_chunked

PASSWORD = "correct horse battery staple for hx datalock"
ENV = os.environ | {"HXDL_TEST_PASSWORD": PASSWORD}


def _init(tmp_path: Path) -> tuple[Path, str]:
    keyring_path = tmp_path / "keyring.hxdl.json"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "hx_datalock.cli",
            "init",
            "--keyring",
            str(keyring_path),
            "--password-env",
            "HXDL_TEST_PASSWORD",
            "--scrypt-n",
            "16384",
            "--allow-low-scrypt-n",
            "--allow-weak-password",
        ],
        check=True,
        env=ENV,
    )
    keyring = load_keyring(keyring_path)
    return keyring_path, keyring.key_id


def _write_chunks(directory: Path, chunks: list[bytes]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for index, chunk in enumerate(chunks):
        (directory / f"chunk-{index}.bin").write_bytes(chunk)


def test_python_seal_is_opened_by_node_and_kotlin(tmp_path: Path) -> None:
    if shutil.which("node") is None or not Path("sdk/node/dist/index.js").is_file():
        pytest.skip("Node SDK build is required")
    if shutil.which("gradle") is None:
        pytest.skip("gradle is required")
    keyring_path, _key_id = _init(tmp_path)
    keyring = load_keyring(keyring_path)
    payload = b"alpha-chunk-manifest" + b"Z" * 20
    manifest, chunks = seal_chunked(
        key_id=keyring.key_id,
        public_key=keyring.public_write_key,
        src=io.BytesIO(payload),
        chunk_size=16,
        file_id="file-a",
    )
    manifest_path = tmp_path / "manifest.json"
    chunk_dir = tmp_path / "chunks"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    _write_chunks(chunk_dir, chunks)

    node_out = tmp_path / "node.txt"
    subprocess.run(
        ["node", "tests/compat/manifest_tool.mjs", "open", str(keyring_path), str(manifest_path), str(chunk_dir), str(node_out)],
        check=True,
        env=ENV,
    )
    assert node_out.read_bytes() == payload

    kotlin_out = tmp_path / "kotlin.txt"
    subprocess.run(
        [
            "gradle",
            "runManifestExample",
            "--quiet",
            f"-PexampleArgs=open|{keyring_path}|{manifest_path}|{chunk_dir}|{kotlin_out}|{PASSWORD}",
        ],
        cwd="sdk/kotlin",
        check=True,
    )
    assert kotlin_out.read_bytes() == payload


def test_node_and_kotlin_seals_open_in_python(tmp_path: Path) -> None:
    if shutil.which("node") is None or not Path("sdk/node/dist/index.js").is_file():
        pytest.skip("Node SDK build is required")
    if shutil.which("gradle") is None:
        pytest.skip("gradle is required")
    keyring_path, _key_id = _init(tmp_path)
    payload = b"bravo" * 9
    plain = tmp_path / "plain.bin"
    plain.write_bytes(payload)

    for name in ("node", "kotlin"):
        out_dir = tmp_path / name
        out_dir.mkdir()
        if name == "node":
            subprocess.run(
                ["node", "tests/compat/manifest_tool.mjs", "seal", str(keyring_path), str(plain), "8", "file-b", str(out_dir)],
                check=True,
                env=ENV,
            )
        else:
            subprocess.run(
                [
                    "gradle",
                    "runManifestExample",
                    "--quiet",
                    f"-PexampleArgs=seal|{keyring_path}|{plain}|8|file-b|{out_dir}|{PASSWORD}",
                ],
                cwd="sdk/kotlin",
                check=True,
            )
        manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
        chunks = [(out_dir / f"chunk-{index}.bin").read_bytes() for index in range(len(manifest["chunks"]))]
        keyring = load_keyring(keyring_path)
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
