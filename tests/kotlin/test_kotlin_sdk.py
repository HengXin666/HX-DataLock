import os
import subprocess
import shutil
from pathlib import Path

import pytest

from hx_datalock import DataEnvelope, decrypt_message, encrypt_message, init_keyring, load_keyring, make_user_data_lock, rewrap_keyring

PASSWORD = "correct horse battery staple for hx datalock"


pytestmark = pytest.mark.skipif(
    shutil.which("gradle") is None,
    reason="gradle is required for kotlin compatibility tests",
)


def test_python_envelope_opens_with_kotlin_example(tmp_path: Path) -> None:
    keyring_path = tmp_path / "keyring.hxdl.json"
    envelope_path = tmp_path / "sealed.hxdl.json"
    opened_path = tmp_path / "opened.txt"
    keyring = init_keyring(keyring_path, PASSWORD, scrypt_n=16384, allow_low_scrypt_n=True)

    encrypt_message(keyring, "Python 到 Kotlin".encode()).write(envelope_path)

    subprocess.run(
        [
            "gradle",
            "runOpenExample",
            "--quiet",
            f"-PexampleArgs={keyring_path}|{envelope_path}|{opened_path}|{PASSWORD}",
        ],
        cwd=Path("sdk/kotlin"),
        check=True,
    )

    assert opened_path.read_bytes() == "Python 到 Kotlin".encode()


def test_kotlin_example_locks_envelope_that_python_opens(tmp_path: Path) -> None:
    keyring_path = tmp_path / "keyring.hxdl.json"
    plain_path = tmp_path / "plain.txt"
    envelope_path = tmp_path / "sealed.hxdl.json"
    keyring = init_keyring(keyring_path, PASSWORD, scrypt_n=16384, allow_low_scrypt_n=True)
    plain_path.write_bytes("Kotlin 到 Python".encode())

    subprocess.run(
        [
            "gradle",
            "runLockExample",
            "--quiet",
            f"-PexampleArgs={keyring_path}|{plain_path}|{envelope_path}|{PASSWORD}",
        ],
        cwd=Path("sdk/kotlin"),
        check=True,
    )

    assert (
        decrypt_message(keyring, PASSWORD, DataEnvelope.read(envelope_path))
        == plain_path.read_bytes()
    )


def test_kotlin_rewrap_keeps_envelopes_open_in_python(tmp_path: Path) -> None:
    keyring_path = tmp_path / "keyring.hxdl.json"
    rewrapped_path = tmp_path / "rewrapped.hxdl.json"
    keyring = init_keyring(keyring_path, PASSWORD, scrypt_n=16384, allow_low_scrypt_n=True)
    envelope = encrypt_message(keyring, b"still mine")
    new_password = "another correct horse battery staple"
    subprocess.run(
        [
            "gradle",
            "runRewrapExample",
            "--quiet",
            f"-PexampleArgs={keyring_path}|{rewrapped_path}|{PASSWORD}|{new_password}|true",
        ],
        cwd=Path("sdk/kotlin"),
        check=True,
    )
    rewrapped = load_keyring(rewrapped_path)
    assert rewrapped.key_id == keyring.key_id
    assert make_user_data_lock(rewrapped, new_password).openBytes(envelope) == b"still mine"
    with pytest.raises(Exception):
        make_user_data_lock(rewrapped, PASSWORD).openBytes(envelope)


def test_python_rewrap_opens_in_kotlin(tmp_path: Path) -> None:
    keyring_path = tmp_path / "keyring.hxdl.json"
    rewrapped_path = tmp_path / "rewrapped.hxdl.json"
    envelope_path = tmp_path / "sealed.hxdl.json"
    opened_path = tmp_path / "opened.txt"
    keyring = init_keyring(keyring_path, PASSWORD, scrypt_n=16384, allow_low_scrypt_n=True)
    encrypt_message(keyring, "rewrapped".encode()).write(envelope_path)
    new_password = "another correct horse battery staple"
    rewrap_keyring(keyring, PASSWORD, new_password, allow_low_scrypt_n=True).write(rewrapped_path)
    subprocess.run(
        [
            "gradle",
            "runOpenExample",
            "--quiet",
            f"-PexampleArgs={rewrapped_path}|{envelope_path}|{opened_path}|{new_password}",
        ],
        cwd=Path("sdk/kotlin"),
        check=True,
        env=os.environ,
    )
    assert opened_path.read_bytes() == b"rewrapped"
