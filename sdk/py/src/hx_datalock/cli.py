from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path

from .constants import RECOMMENDED_MIN_SCRYPT_N
from .sdk import (
    DEFAULT_SCRYPT_N,
    DataLockError,
    DataLockErrorCode,
    PublicKeyDocument,
    export_public_key_document,
    init_keyring,
    load_keyring,
    makeSenderDataLock,
    makeUserDataLock,
    verify_keyring_file,
    verify_public_key_document_file,
)


def _fail(code: str, message: str) -> None:
    raise SystemExit(f"HXDL_ERROR code={code} message={message}")


def _read_password(password_env: str | None, *, confirm: bool = False, password_stdin: bool = False) -> str:
    if password_env and password_stdin:
        _fail("INVALID_ARGUMENT", "Pass only one of --password-env and --password-stdin")
    if password_stdin:
        value = sys.stdin.readline()
        if value.endswith("\n"):
            value = value[:-1]
        if value.endswith("\r"):
            value = value[:-1]
        if not value:
            _fail("MISSING_MASTER_PASSWORD", "stdin did not contain a Master Password")
        return value
    if password_env:
        value = os.environ.get(password_env)
        if not value:
            _fail("MISSING_MASTER_PASSWORD_ENV", f"Environment variable {password_env} is empty or missing")
        return value
    password = getpass.getpass("Master password: ")
    if confirm:
        confirmation = getpass.getpass("Confirm master password: ")
        if password != confirmation:
            _fail("MISMATCHED_MASTER_PASSWORD_CONFIRMATION", "Master Password confirmation does not match")
    return password


def _report_password_strength(report: dict) -> None:
    """Print the Password Strength Report. Creation still enforces the policy."""
    entropy = report.get("estimatedEntropyBits")
    score = report.get("score")
    extra = ""
    if entropy is not None:
        extra += f" entropyBits={entropy}"
    if score is not None:
        extra += f" score={score}"
    print(f"Master Password strength: {report['level']} allowed={report['allowed']}{extra}")
    for warning in report.get("warnings", []):
        print(f"  warning: {warning}")
    for suggestion in report.get("suggestions", []):
        print(f"  suggestion: {suggestion}")


def _cmd_init(args: argparse.Namespace) -> None:
    if args.public_keyring:
        print(
            "DANGER: this Keyring is being created for public storage. Anyone who downloads it "
            "can guess the Master Password offline. The password must measure at least 80 bits. "
            "Prefer a private Keyring and publish only the Public Key Document.",
            file=sys.stderr,
        )
    if args.generate_password:
        password = secrets.token_urlsafe(18)
        print(
            "Generated Master Password (save it offline; it is not stored in the Keyring):",
            file=sys.stderr,
        )
        print(password, file=sys.stderr)
    else:
        password = _read_password(args.password_env, confirm=True, password_stdin=args.password_stdin)
    if args.scrypt_n < RECOMMENDED_MIN_SCRYPT_N:
        print(
            f"warning: scrypt N={args.scrypt_n} is below the recommended {RECOMMENDED_MIN_SCRYPT_N}",
            file=sys.stderr,
        )
    keyring = init_keyring(
        args.keyring,
        password,
        scrypt_n=args.scrypt_n,
        on_password_report=_report_password_strength,
        allow_weak=args.allow_weak,
        public_keyring=args.public_keyring,
    )
    print(f"Keyring written: {args.keyring}")
    print(f"Write Key ID: {keyring.key_id}")
    print("Keyring storage: private local file. Publish the Public Key Document, not this file.")


def _cmd_lock(args: argparse.Namespace) -> None:
    document = PublicKeyDocument.read(args.public)
    if not args.expect_key_id and not args.allow_unpinned_key:
        _fail(
            DataLockErrorCode.UNPINNED_PUBLIC_KEY.value,
            "lock requires --expect-key-id. Pass --allow-unpinned-key only if you accept a replaced Public Key Document.",
        )
    sender = makeSenderDataLock(
        document,
        expected_key_id=args.expect_key_id,
        require_expected_key_id=not args.allow_unpinned_key,
    )
    sender.lockFile(args.input, args.output)
    print(f"Data Envelope written: {args.output}")


def _cmd_open(args: argparse.Namespace) -> None:
    user = makeUserDataLock(
        load_keyring(args.keyring),
        _read_password(args.password_env, password_stdin=args.password_stdin),
    )
    user.openFile(args.input, args.output)
    print(f"Plaintext written: {args.output}")


def _cmd_verify_keyring(args: argparse.Namespace) -> None:
    keyring = verify_keyring_file(args.keyring, require_stable_json=True)
    print(f"Valid Keyring: {keyring.key_id}")


def _cmd_verify_public(args: argparse.Namespace) -> None:
    public_key_document = verify_public_key_document_file(args.public, require_stable_json=True)
    print(f"Valid Public Key Document: {public_key_document.key_id}")


def _cmd_public_key(args: argparse.Namespace) -> None:
    keyring = load_keyring(args.keyring)
    document = export_public_key_document(keyring)
    if args.output:
        document.write(args.output)
        print(f"Public Key Document written: {args.output}")
    print(f"Write Key ID: {document.key_id}")


def _emit_measurement(operation: str, size_bytes: int, elapsed_ms: float) -> None:
    print(
        json.dumps(
            {
                "operation": operation,
                "sizeBytes": size_bytes,
                "elapsedMs": round(elapsed_ms, 3),
            },
            sort_keys=True,
        )
    )


def _cmd_bench(args: argparse.Namespace) -> None:
    keyring = load_keyring(args.keyring)
    master_password = _read_password(args.password_env, password_stdin=args.password_stdin)
    sizes = [int(item) for item in args.sizes.split(",")]

    started = time.perf_counter()
    user = makeUserDataLock(keyring, {"masterPassword": master_password})
    _emit_measurement("unlockKeyring", sizes[0], (time.perf_counter() - started) * 1000)

    with tempfile.TemporaryDirectory(prefix="hxdl-bench-") as temp_dir:
        temp_path = Path(temp_dir)
        for size_bytes in sizes:
            payload = b"x" * size_bytes

            started = time.perf_counter()
            envelope = user.lockBytes(payload)
            _emit_measurement("lockBytes", size_bytes, (time.perf_counter() - started) * 1000)

            started = time.perf_counter()
            user.openBytes(envelope)
            _emit_measurement("openBytes", size_bytes, (time.perf_counter() - started) * 1000)

            input_path = temp_path / f"payload-{size_bytes}.bin"
            envelope_path = temp_path / f"payload-{size_bytes}.hxdl.json"
            output_path = temp_path / f"opened-{size_bytes}.bin"
            input_path.write_bytes(payload)

            started = time.perf_counter()
            user.lockFile(input_path, envelope_path)
            _emit_measurement("lockFile", size_bytes, (time.perf_counter() - started) * 1000)

            started = time.perf_counter()
            user.openFile(envelope_path, output_path)
            _emit_measurement("openFile", size_bytes, (time.perf_counter() - started) * 1000)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hxdl",
        description="HX-DataLock write-only encryption CLI",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    init = subcommands.add_parser("init", help="create a private local Keyring")
    init.add_argument("--keyring", default="keyring.hxdl.json")
    init.add_argument("--password-env")
    init.add_argument("--password-stdin", action="store_true", help="read the Master Password from one stdin line")
    init.add_argument("--scrypt-n", type=int, default=DEFAULT_SCRYPT_N)
    init.add_argument("--allow-weak", action="store_true", help="create a Keyring even when the strength report rejects the password")
    init.add_argument(
        "--public-keyring",
        action="store_true",
        help="DANGER: opt into a Keyring that may be published. Requires an 80-bit Master Password.",
    )
    init.add_argument("--generate-password", action="store_true", help="generate a random Master Password and print it once to stderr")
    init.set_defaults(func=_cmd_init)

    lock = subcommands.add_parser("lock", help="lock a local file with a Public Key Document")
    lock.add_argument("--public", required=True)
    lock.add_argument("--expect-key-id", help="required unless --allow-unpinned-key is set")
    lock.add_argument("--allow-unpinned-key", action="store_true")
    lock.add_argument("--in", dest="input", required=True)
    lock.add_argument("--out", dest="output", required=True)
    lock.set_defaults(func=_cmd_lock)

    open_ = subcommands.add_parser("open", help="decrypt a Data Envelope locally")
    open_.add_argument("--keyring", default="keyring.hxdl.json")
    open_.add_argument("--in", dest="input", required=True)
    open_.add_argument("--out", dest="output", required=True)
    open_.add_argument("--password-env")
    open_.add_argument("--password-stdin", action="store_true")
    open_.set_defaults(func=_cmd_open)

    verify = subcommands.add_parser("verify-keyring", help="verify a Keyring")
    verify.add_argument("--keyring", default="keyring.hxdl.json")
    verify.set_defaults(func=_cmd_verify_keyring)

    verify_public = subcommands.add_parser("verify-public", help="verify a Public Key Document")
    verify_public.add_argument("--public", required=True)
    verify_public.set_defaults(func=_cmd_verify_public)

    bench = subcommands.add_parser("bench", help="measure v1 Keyring and Data Envelope operations")
    bench.add_argument("--keyring", default="keyring.hxdl.json")
    bench.add_argument("--password-env")
    bench.add_argument("--password-stdin", action="store_true")
    bench.add_argument("--sizes", default="1048576,10485760,26214400")
    bench.set_defaults(func=_cmd_bench)

    public_key = subcommands.add_parser("export-public", help="export the public Write Key")
    public_key.add_argument("--keyring", default="keyring.hxdl.json")
    public_key.add_argument("--out", dest="output")
    public_key.set_defaults(func=_cmd_public_key)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    if hasattr(args, "input"):
        args.input = Path(args.input)
    if hasattr(args, "output"):
        args.output = Path(args.output)
    try:
        args.func(args)
    except DataLockError as exc:
        _fail(exc.code.value, str(exc))


if __name__ == "__main__":
    main()
