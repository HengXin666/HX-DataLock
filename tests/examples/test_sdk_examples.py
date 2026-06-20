import os
import subprocess
import sys
from pathlib import Path


PASSWORD = "correct horse battery staple for hx datalock"


def test_python_examples_send_and_decrypt_message(tmp_path: Path) -> None:
    keyring_path = tmp_path / "keyring.hxdl.json"
    public_path = tmp_path / "public.hxdl.json"
    plain_path = tmp_path / "plain.txt"
    envelope_path = tmp_path / "plain.hxdl.json"
    opened_path = tmp_path / "opened.txt"
    env = os.environ | {"HXDL_TEST_PASSWORD": PASSWORD}

    plain_path.write_text("python example payload", encoding="utf-8")
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
        ],
        check=True,
        env=env,
    )
    subprocess.run(
        [
            sys.executable,
            "-m",
            "hx_datalock.cli",
            "export-public",
            "--keyring",
            str(keyring_path),
            "--out",
            str(public_path),
        ],
        check=True,
    )

    subprocess.run(
        [
            sys.executable,
            "examples/py/send_message.py",
            "--public",
            str(public_path),
            "--in",
            str(plain_path),
            "--out",
            str(envelope_path),
        ],
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            "examples/py/decrypt_message.py",
            "--keyring",
            str(keyring_path),
            "--in",
            str(envelope_path),
            "--out",
            str(opened_path),
            "--password-env",
            "HXDL_TEST_PASSWORD",
        ],
        check=True,
        env=env,
    )

    assert opened_path.read_text(encoding="utf-8") == "python example payload"


def test_node_example_locks_with_public_document_and_opens_with_keyring(tmp_path: Path) -> None:
    keyring_path = tmp_path / "keyring.hxdl.json"
    public_path = tmp_path / "public.hxdl.json"
    plain_path = tmp_path / "plain.txt"
    envelope_path = tmp_path / "plain.hxdl.json"
    opened_path = tmp_path / "opened.txt"
    env = os.environ | {"HXDL_TEST_PASSWORD": PASSWORD}

    plain_path.write_text("node example payload", encoding="utf-8")
    subprocess.run(
        [
            "node",
            "sdk/node/hx-datalock.mjs",
            "init",
            "--keyring",
            str(keyring_path),
            "--password-env",
            "HXDL_TEST_PASSWORD",
            "--scrypt-n",
            "16384",
        ],
        check=True,
        env=env,
    )
    subprocess.run(
        [
            "node",
            "sdk/node/hx-datalock.mjs",
            "export-public",
            "--keyring",
            str(keyring_path),
            "--out",
            str(public_path),
        ],
        check=True,
    )

    subprocess.run(
        [
            "node",
            "examples/node/lock_and_open_file.mjs",
            "--public",
            str(public_path),
            "--keyring",
            str(keyring_path),
            "--in",
            str(plain_path),
            "--envelope",
            str(envelope_path),
            "--out",
            str(opened_path),
            "--password-env",
            "HXDL_TEST_PASSWORD",
        ],
        check=True,
        env=env,
    )

    assert opened_path.read_text(encoding="utf-8") == "node example payload"
