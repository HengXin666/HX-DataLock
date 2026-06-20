import subprocess
import shutil
from pathlib import Path

import pytest

from hx_datalock import DataEnvelope, decrypt_message, encrypt_message, init_keyring


PASSWORD = "correct horse battery staple for hx datalock"


pytestmark = pytest.mark.skipif(shutil.which("gradle") is None, reason="gradle is required for Knolin compatibility tests")


def test_python_envelope_opens_with_knolin_example(tmp_path: Path) -> None:
    keyring_path = tmp_path / "keyring.hxdl.json"
    envelope_path = tmp_path / "sealed.hxdl.json"
    opened_path = tmp_path / "opened.txt"
    keyring = init_keyring(keyring_path, PASSWORD, scrypt_n=16384)

    encrypt_message(keyring, "Python 到 Kotlin".encode()).write(envelope_path)

    subprocess.run(
        [
            "gradle",
            "runOpenExample",
            "--quiet",
            f"-PexampleArgs={keyring_path}|{envelope_path}|{opened_path}|{PASSWORD}",
        ],
        cwd=Path("sdk/knolin"),
        check=True,
    )

    assert opened_path.read_bytes() == "Python 到 Kotlin".encode()


def test_knolin_example_locks_envelope_that_python_opens(tmp_path: Path) -> None:
    keyring_path = tmp_path / "keyring.hxdl.json"
    plain_path = tmp_path / "plain.txt"
    envelope_path = tmp_path / "sealed.hxdl.json"
    keyring = init_keyring(keyring_path, PASSWORD, scrypt_n=16384)
    plain_path.write_bytes("Kotlin 到 Python".encode())

    subprocess.run(
        [
            "gradle",
            "runLockExample",
            "--quiet",
            f"-PexampleArgs={keyring_path}|{plain_path}|{envelope_path}|{PASSWORD}",
        ],
        cwd=Path("sdk/knolin"),
        check=True,
    )

    assert decrypt_message(keyring, PASSWORD, DataEnvelope.read(envelope_path)) == plain_path.read_bytes()
