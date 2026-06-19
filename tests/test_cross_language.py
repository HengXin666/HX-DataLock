import os
import subprocess
from pathlib import Path

from hx_datalock import (
    DataEnvelope,
    decrypt_message,
    encrypt_message,
    init_keyring,
    load_keyring,
    open_file,
    send_file,
)


def test_python_encrypts_and_node_decrypts(tmp_path: Path) -> None:
    password = "correct horse battery staple for hx datalock"
    keyring_path = tmp_path / "keyring.hxdl.json"
    plain_path = tmp_path / "plain.txt"
    envelope_path = tmp_path / "sealed.hxdl.json"
    decrypted_path = tmp_path / "decrypted.txt"

    env = os.environ | {"HXDL_TEST_PASSWORD": password}
    subprocess.run(
        [
            "node",
            "scripts/hx-datalock.mjs",
            "init",
            "--out",
            str(keyring_path),
            "--password-env",
            "HXDL_TEST_PASSWORD",
            "--scrypt-n",
            "16384",
        ],
        check=True,
        env=env,
    )

    keyring = load_keyring(keyring_path)
    plain_path.write_bytes(b"python sender, node receiver")
    encrypt_message(keyring, plain_path.read_bytes()).write(envelope_path)

    subprocess.run(
        [
            "node",
            "scripts/hx-datalock.mjs",
            "decrypt",
            "--keyring",
            str(keyring_path),
            "--in",
            str(envelope_path),
            "--out",
            str(decrypted_path),
            "--password-env",
            "HXDL_TEST_PASSWORD",
        ],
        check=True,
        env=env,
    )
    assert decrypted_path.read_bytes() == plain_path.read_bytes()


def test_node_encrypts_and_python_decrypts(tmp_path: Path) -> None:
    password = "correct horse battery staple for hx datalock"
    keyring_path = tmp_path / "keyring.hxdl.json"
    plain_path = tmp_path / "plain.txt"
    envelope_path = tmp_path / "sealed.hxdl.json"

    env = os.environ | {"HXDL_TEST_PASSWORD": password}
    subprocess.run(
        [
            "node",
            "scripts/hx-datalock.mjs",
            "init",
            "--out",
            str(keyring_path),
            "--password-env",
            "HXDL_TEST_PASSWORD",
            "--scrypt-n",
            "16384",
        ],
        check=True,
        env=env,
    )
    plain_path.write_bytes(b"node sender, python receiver")
    subprocess.run(
        [
            "node",
            "scripts/hx-datalock.mjs",
            "encrypt",
            "--keyring",
            str(keyring_path),
            "--in",
            str(plain_path),
            "--out",
            str(envelope_path),
        ],
        check=True,
    )

    keyring = load_keyring(keyring_path)
    plaintext = decrypt_message(keyring, password, DataEnvelope.read(envelope_path))
    assert plaintext == plain_path.read_bytes()


def test_simple_python_api_round_trips_file(tmp_path: Path) -> None:
    password = "correct horse battery staple for hx datalock"
    keyring_path = tmp_path / "keyring.hxdl.json"
    plain_path = tmp_path / "plain.txt"
    envelope_path = tmp_path / "sealed.hxdl.json"
    decrypted_path = tmp_path / "decrypted.txt"

    init_keyring(keyring_path, password, scrypt_n=16384)
    plain_path.write_bytes(b"simple api, hidden internals")

    send_file(keyring_path, plain_path, envelope_path)
    open_file(keyring_path, envelope_path, decrypted_path, password)

    assert decrypted_path.read_bytes() == plain_path.read_bytes()
