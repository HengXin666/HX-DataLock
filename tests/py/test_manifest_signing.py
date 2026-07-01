from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


SCRIPT = Path("scripts/hxdl-manifest-sign.py")


def test_manifest_signing_prototype_signs_and_verifies_manifest(tmp_path: Path) -> None:
    manifest_path = tmp_path / "compatibility.json"
    signed_path = tmp_path / "compatibility.signed.json"
    manifest_path.write_text(
        json.dumps({"schema": "hxdl.compatibilityManifest.v1", "cases": []}, indent=2) + "\n",
        encoding="utf-8",
    )
    env = os.environ | {"HXDL_MANIFEST_SIGNING_SECRET": "test manifest signing secret"}

    sign = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "sign",
            "--manifest",
            str(manifest_path),
            "--out",
            str(signed_path),
            "--key-id",
            "manifest:test",
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert sign.returncode == 0, sign.stderr

    signed = json.loads(signed_path.read_text(encoding="utf-8"))
    assert signed["schema"] == "hxdl.signedManifest.v1"
    assert signed["payload"]["schema"] == "hxdl.compatibilityManifest.v1"
    assert signed["signature"]

    verify = subprocess.run(
        [sys.executable, str(SCRIPT), "verify", "--signed", str(signed_path)],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert verify.returncode == 0, verify.stderr
    assert "Valid signed manifest: manifest:test" in verify.stdout


def test_manifest_signing_prototype_rejects_tampered_manifest(tmp_path: Path) -> None:
    manifest_path = tmp_path / "compatibility.json"
    signed_path = tmp_path / "compatibility.signed.json"
    manifest_path.write_text(
        json.dumps({"schema": "hxdl.compatibilityManifest.v1", "cases": []}, indent=2) + "\n",
        encoding="utf-8",
    )
    env = os.environ | {"HXDL_MANIFEST_SIGNING_SECRET": "test manifest signing secret"}
    subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "sign",
            "--manifest",
            str(manifest_path),
            "--out",
            str(signed_path),
            "--key-id",
            "manifest:test",
        ],
        env=env,
        check=True,
    )
    signed = json.loads(signed_path.read_text(encoding="utf-8"))
    signed["payload"]["cases"].append({"id": "tampered"})
    signed_path.write_text(json.dumps(signed, indent=2) + "\n", encoding="utf-8")

    verify = subprocess.run(
        [sys.executable, str(SCRIPT), "verify", "--signed", str(signed_path)],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert verify.returncode != 0
    assert "signature mismatch" in verify.stderr
