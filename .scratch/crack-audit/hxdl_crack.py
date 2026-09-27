#!/usr/bin/env python3
"""HX-DataLock Keyring 离线爆破台 (本地审计用)

威胁模型 (来自 ADR 0001 / 0019):
  攻击者拿到 keyring.json 副本 -> 无需任何交互 -> 对 Master Password 做离线猜测。
  scrypt 是唯一的减速带, 没有锁定, 没有服务端。

用法:
  uv run python hxdl_crack.py --keyring K.json --wordlist W.txt --jobs 8
"""
from __future__ import annotations

import argparse, base64, hashlib, json, os, secrets, sys, time, unicodedata
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, "/home/hx/Loli/code/HXLoLis/utils/HX-DataLock/sdk/py/src")
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEYRING_SCHEMA = "hxdl.keyring.v1"


def _b64d(v: str) -> bytes:
    return base64.b64decode(v, validate=True)


def aad_for(key_id: str) -> bytes:
    return f"{KEYRING_SCHEMA}:{key_id}:scrypt:AES-256-GCM".encode("utf-8")


def try_password(password: str, enc: dict, key_id: str) -> bool:
    """只看 AES-GCM tag 是否验证通过; 不做 DER 解析 (那会额外泄露时序)。"""
    kdf = enc["kdf"]
    try:
        wrapping_key = Scrypt(
            salt=_b64d(kdf["salt"]),
            length=kdf["keyLength"],
            n=kdf["N"], r=kdf["r"], p=kdf["p"],
        ).derive(unicodedata.normalize("NFC", password).encode("utf-8"))
        nonce = _b64d(enc["aead"]["nonce"])
        tag = _b64d(enc["aead"]["tag"])
        ct = _b64d(enc["ciphertext"])
        AESGCM(wrapping_key).decrypt(nonce, ct + tag, aad_for(key_id))
        return True
    except Exception:
        return False


def _worker(args):
    chunk, enc, key_id = args
    for pw in chunk:
        if try_password(pw, enc, key_id):
            return pw
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keyring", required=True)
    ap.add_argument("--wordlist", required=True)
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    ap.add_argument("--chunk", type=int, default=32)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--expect", default="")
    args = ap.parse_args()

    keyring = json.loads(Path(args.keyring).read_text(encoding="utf-8"))
    key_id = keyring["publicWriteKey"]["keyId"]
    enc = keyring["encryptedReadKey"]
    kdf = enc["kdf"]
    words = [w.rstrip("\n") for w in Path(args.wordlist).read_text(encoding="utf-8", errors="replace").splitlines()]
    words = [w for w in words if w]
    if args.limit:
        words = words[: args.limit]

    # 单猜成本
    t0 = time.perf_counter()
    try_password("__warmup__", enc, key_id)
    per_guess = time.perf_counter() - t0

    print(json.dumps({
        "event": "plan", "scrypt_N": kdf["N"], "scrypt_r": kdf["r"], "scrypt_p": kdf["p"],
        "candidates": len(words), "jobs": args.jobs,
        "single_guess_ms": round(per_guess * 1000, 1),
        "attacker_guesses_per_sec_per_core": round(1 / per_guess, 2),
        "serial_eta_sec": round(per_guess * len(words), 1),
        "parallel_eta_sec": round(per_guess * len(words) / max(1, args.jobs), 1),
    }))

    if per_guess * len(words) / max(1, args.jobs) > 3600:
        print(json.dumps({"event": "warn", "msg": "预计超过 1 小时, 建议 --limit 或降低 N"}))

    chunks = [(words[i : i + args.chunk], enc, key_id) for i in range(0, len(words), args.chunk)]
    started = time.perf_counter()
    found = None
    tried = 0
    with ProcessPoolExecutor(max_workers=args.jobs) as pool:
        for result in pool.map(_worker, chunks):
            tried += args.chunk
            if result:
                found = result
                pool.shutdown(wait=False, cancel_futures=True)
                break
    elapsed = time.perf_counter() - started

    out = {
        "event": "result",
        "found": found is not None,
        "password": found,
        "candidates_tried": tried,
        "elapsed_sec": round(elapsed, 2),
        "guesses_per_sec": round(tried / elapsed, 1) if elapsed else None,
        "expect_match": (found == args.expect) if args.expect else None,
    }
    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    main()
