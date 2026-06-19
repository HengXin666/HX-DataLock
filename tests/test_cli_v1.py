import json
import os
import subprocess
import sys
from pathlib import Path


PASSWORD = "correct horse battery staple for hx datalock"


def run_hxdl(
    *args: str,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    command_env = os.environ.copy()
    if env:
        command_env.update(env)
    return subprocess.run(
        [sys.executable, "-m", "hx_datalock.cli", *args],
        input=input_text,
        text=True,
        capture_output=True,
        env=command_env,
        check=False,
    )


def test_cli_init_confirms_master_password_interactively(tmp_path: Path) -> None:
    keyring_path = tmp_path / "keyring.hxdl.json"

    result = run_hxdl(
        "init",
        "--keyring",
        str(keyring_path),
        "--scrypt-n",
        "16384",
        input_text=f"{PASSWORD}\n{PASSWORD}\n",
    )

    assert result.returncode == 0, result.stderr
    keyring = json.loads(keyring_path.read_text(encoding="utf-8"))
    assert keyring["schema"] == "hxdl.keyring.v1"
    assert keyring["encryptedReadKey"]


def test_cli_init_rejects_mismatched_interactive_confirmation(tmp_path: Path) -> None:
    keyring_path = tmp_path / "keyring.hxdl.json"

    result = run_hxdl(
        "init",
        "--keyring",
        str(keyring_path),
        "--scrypt-n",
        "16384",
        input_text=f"{PASSWORD}\nwrong password\n",
    )

    assert result.returncode != 0
    assert not keyring_path.exists()
    assert "MISMATCHED_MASTER_PASSWORD_CONFIRMATION" in result.stderr


def test_cli_v1_export_public_lock_and_open_round_trip(tmp_path: Path) -> None:
    keyring_path = tmp_path / "keyring.hxdl.json"
    public_path = tmp_path / "public.hxdl.json"
    plaintext_path = tmp_path / "payload.bin"
    envelope_path = tmp_path / "payload.hxdl.json"
    opened_path = tmp_path / "opened.bin"
    env = {"HXDL_MASTER_PASSWORD": PASSWORD}

    init_result = run_hxdl(
        "init",
        "--keyring",
        str(keyring_path),
        "--password-env",
        "HXDL_MASTER_PASSWORD",
        "--scrypt-n",
        "16384",
        env=env,
    )
    assert init_result.returncode == 0, init_result.stderr

    export_result = run_hxdl(
        "export-public",
        "--keyring",
        str(keyring_path),
        "--out",
        str(public_path),
    )
    assert export_result.returncode == 0, export_result.stderr
    public_document = json.loads(public_path.read_text(encoding="utf-8"))
    assert public_document["schema"] == "hxdl.publicKey.v1"
    assert "encryptedReadKey" not in public_document

    plaintext_path.write_bytes(b"cli v1 payload")
    lock_result = run_hxdl(
        "lock",
        "--public",
        str(public_path),
        "--in",
        str(plaintext_path),
        "--out",
        str(envelope_path),
    )
    assert lock_result.returncode == 0, lock_result.stderr

    open_result = run_hxdl(
        "open",
        "--keyring",
        str(keyring_path),
        "--password-env",
        "HXDL_MASTER_PASSWORD",
        "--in",
        str(envelope_path),
        "--out",
        str(opened_path),
        env=env,
    )
    assert open_result.returncode == 0, open_result.stderr
    assert opened_path.read_bytes() == b"cli v1 payload"

    rejected_lock = run_hxdl(
        "lock",
        "--public",
        str(keyring_path),
        "--in",
        str(plaintext_path),
        "--out",
        str(tmp_path / "rejected.hxdl.json"),
    )
    assert rejected_lock.returncode != 0
    assert "INVALID_PUBLIC_KEY_DOCUMENT" in rejected_lock.stderr


def test_cli_verify_keyring_and_public_do_not_require_master_password(tmp_path: Path) -> None:
    keyring_path = tmp_path / "keyring.hxdl.json"
    public_path = tmp_path / "public.hxdl.json"
    env = {"HXDL_MASTER_PASSWORD": PASSWORD}

    assert (
        run_hxdl(
            "init",
            "--keyring",
            str(keyring_path),
            "--password-env",
            "HXDL_MASTER_PASSWORD",
            "--scrypt-n",
            "16384",
            env=env,
        ).returncode
        == 0
    )
    assert (
        run_hxdl("export-public", "--keyring", str(keyring_path), "--out", str(public_path)).returncode
        == 0
    )

    keyring_result = run_hxdl("verify-keyring", "--keyring", str(keyring_path))
    public_result = run_hxdl("verify-public", "--public", str(public_path))

    assert keyring_result.returncode == 0, keyring_result.stderr
    assert public_result.returncode == 0, public_result.stderr
    assert "Valid Keyring" in keyring_result.stdout
    assert "Valid Public Key Document" in public_result.stdout

    tampered_public = json.loads(public_path.read_text(encoding="utf-8"))
    tampered_public["publicWriteKey"]["keyId"] = "x25519:wrong"
    public_path.write_text(json.dumps(tampered_public), encoding="utf-8")

    invalid_public_result = run_hxdl("verify-public", "--public", str(public_path))
    assert invalid_public_result.returncode != 0
    assert "INVALID_PUBLIC_KEY_DOCUMENT" in invalid_public_result.stderr


def test_cli_verify_rejects_documents_that_do_not_use_stable_json(tmp_path: Path) -> None:
    keyring_path = tmp_path / "keyring.hxdl.json"
    public_path = tmp_path / "public.hxdl.json"
    env = {"HXDL_MASTER_PASSWORD": PASSWORD}

    assert (
        run_hxdl(
            "init",
            "--keyring",
            str(keyring_path),
            "--password-env",
            "HXDL_MASTER_PASSWORD",
            "--scrypt-n",
            "16384",
            env=env,
        ).returncode
        == 0
    )
    assert (
        run_hxdl("export-public", "--keyring", str(keyring_path), "--out", str(public_path)).returncode
        == 0
    )

    keyring_path.write_text(
        json.dumps(json.loads(keyring_path.read_text(encoding="utf-8")), separators=(",", ":")),
        encoding="utf-8",
    )
    public_path.write_text(
        json.dumps(json.loads(public_path.read_text(encoding="utf-8")), separators=(",", ":")),
        encoding="utf-8",
    )

    keyring_result = run_hxdl("verify-keyring", "--keyring", str(keyring_path))
    public_result = run_hxdl("verify-public", "--public", str(public_path))

    assert keyring_result.returncode != 0
    assert public_result.returncode != 0
    assert "INVALID_KEYRING" in keyring_result.stderr
    assert "INVALID_PUBLIC_KEY_DOCUMENT" in public_result.stderr


def test_cli_bench_reports_v1_operations_as_json_lines(tmp_path: Path) -> None:
    keyring_path = tmp_path / "keyring.hxdl.json"
    env = {"HXDL_MASTER_PASSWORD": PASSWORD}
    assert (
        run_hxdl(
            "init",
            "--keyring",
            str(keyring_path),
            "--password-env",
            "HXDL_MASTER_PASSWORD",
            "--scrypt-n",
            "16384",
            env=env,
        ).returncode
        == 0
    )

    result = run_hxdl(
        "bench",
        "--keyring",
        str(keyring_path),
        "--password-env",
        "HXDL_MASTER_PASSWORD",
        "--sizes",
        "1024",
        env=env,
    )

    assert result.returncode == 0, result.stderr
    measurements = [json.loads(line) for line in result.stdout.splitlines()]
    assert {item["operation"] for item in measurements} == {
        "unlockKeyring",
        "lockBytes",
        "openBytes",
        "lockFile",
        "openFile",
    }
    assert {item["sizeBytes"] for item in measurements} == {1024}
    assert all(item["elapsedMs"] >= 0 for item in measurements)
