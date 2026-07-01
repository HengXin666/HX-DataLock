#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any


def stable_json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def sign_payload(payload: dict[str, Any], secret: bytes) -> str:
    return b64url(hmac.new(secret, stable_json_bytes(payload), hashlib.sha256).digest())


def load_secret(env_name: str) -> bytes:
    value = os.environ.get(env_name)
    if not value:
        raise SystemExit(f"error: environment variable {env_name} is empty or missing")
    return value.encode("utf-8")


def load_json(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit("error: manifest JSON must be an object")
    return value


def command_sign(args: argparse.Namespace) -> None:
    payload = load_json(args.manifest)
    secret = load_secret(args.secret_env)
    signed = {
        "schema": "hxdl.signedManifest.v1",
        "signedAt": dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "issuer": args.issuer,
        "keyId": args.key_id,
        "alg": "HMAC-SHA256",
        "payload": payload,
        "signature": sign_payload(payload, secret),
    }
    Path(args.out).write_bytes(stable_json_bytes(signed))


def command_verify(args: argparse.Namespace) -> None:
    signed = load_json(args.signed)
    if signed.get("schema") != "hxdl.signedManifest.v1":
        raise SystemExit("error: unsupported signed manifest schema")
    if signed.get("alg") != "HMAC-SHA256":
        raise SystemExit("error: unsupported signed manifest algorithm")
    payload = signed.get("payload")
    if not isinstance(payload, dict):
        raise SystemExit("error: signed manifest payload must be an object")
    expected = sign_payload(payload, load_secret(args.secret_env))
    if not hmac.compare_digest(str(signed.get("signature")), expected):
        raise SystemExit("error: signed manifest signature mismatch")
    print(f"Valid signed manifest: {signed.get('keyId')}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prototype HX-DataLock manifest signing helper")
    subcommands = parser.add_subparsers(dest="command", required=True)

    sign = subcommands.add_parser("sign")
    sign.add_argument("--manifest", required=True)
    sign.add_argument("--out", required=True)
    sign.add_argument("--key-id", required=True)
    sign.add_argument("--secret-env", default="HXDL_MANIFEST_SIGNING_SECRET")
    sign.add_argument("--issuer", default="hx-datalock")
    sign.set_defaults(func=command_sign)

    verify = subcommands.add_parser("verify")
    verify.add_argument("--signed", required=True)
    verify.add_argument("--secret-env", default="HXDL_MANIFEST_SIGNING_SECRET")
    verify.set_defaults(func=command_verify)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
