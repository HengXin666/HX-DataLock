#!/usr/bin/env python3
"""多目标离线爆破: 一份候选表, 打全部目标, 记录命中的排名与耗时。

候选来源必须是**真实泄露口令表**, 不用随机串 (随机串只作为上界参照)。
"""
from __future__ import annotations
import argparse, base64, json, os, sys, time, unicodedata
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, "/home/hx/Loli/code/HXLoLis/utils/HX-DataLock/sdk/py/src")
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SCHEMA = "hxdl.keyring.v1"

def check(pw: str, enc: dict, key_id: str) -> bool:
    if not isinstance(pw, str):
        raise TypeError(f"password must be str, got {type(pw).__name__}")
    try:
        kdf = enc["kdf"]
        wk = Scrypt(salt=base64.b64decode(kdf["salt"]), length=kdf["keyLength"],
                    n=kdf["N"], r=kdf["r"], p=kdf["p"]).derive(
                        unicodedata.normalize("NFC", pw).encode("utf-8"))
        AESGCM(wk).decrypt(base64.b64decode(enc["aead"]["nonce"]),
                           base64.b64decode(enc["ciphertext"]) + base64.b64decode(enc["aead"]["tag"]),
                           f"{SCHEMA}:{key_id}:scrypt:AES-256-GCM".encode())
        return True
    except Exception:
        return False

def _one(job):
    chunk, targets = job
    if isinstance(chunk, str):
        chunk = [chunk]
    for pw in chunk:
        for t in targets:
            if check(pw, t["enc"], t["key_id"]):
                return (t["case"], pw)
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wordlist", required=True)
    ap.add_argument("--targets", required=True)
    ap.add_argument("--jobs", type=int, default=24)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--rules", action="store_true", help="启用常见变形规则")
    ap.add_argument("--label", default="")
    args = ap.parse_args()

    idx = json.loads(Path(args.targets).read_text(encoding="utf-8"))
    targets = []
    for e in idx:
        kr = json.loads(Path(e["keyring"]).read_text(encoding="utf-8"))
        targets.append({"case": e["case"], "tier": e["tier"], "pw": e["password"],
                        "enc": kr["encryptedReadKey"], "key_id": kr["publicWriteKey"]["keyId"]})
    N = targets[0]["enc"]["kdf"]["N"]

    base = [w.rstrip("\n") for w in Path(args.wordlist).read_text(encoding="utf-8", errors="replace").splitlines()]
    base = [w for w in base if w and len(w) < 64]
    if args.limit:
        base = base[: args.limit]

    cands = list(base)
    if args.rules:
        extra = []
        for w in base[:5000]:
            c = w.capitalize()
            extra += [c, w + "1", w + "123", w + "!", c + "1", c + "123", c + "!"]
            for y in ("2023", "2024", "2025", "2026", "1990"):
                extra.append(w + y); extra.append(c + y)
        cands = list(dict.fromkeys(cands + extra))

    print(json.dumps({"event": "start", "label": args.label, "scrypt_N": N,
                      "targets": len(targets), "candidates": len(cands), "jobs": args.jobs}), flush=True)

    pending = {t["case"]: t for t in targets}
    found, t0 = {}, time.perf_counter()
    CH = 8
    jobs = [(cands[i:i+CH], targets) for i in range(0, len(cands), CH)]
    tried = 0
    with ProcessPoolExecutor(max_workers=args.jobs) as pool:
        for res in pool.map(_one, jobs, chunksize=1):
            tried += CH
            if res:
                case, pw = res
                if case not in found:
                    found[case] = {"password": pw, "rank": tried, "elapsed_sec": round(time.perf_counter()-t0, 1)}
                    print(json.dumps({"event": "cracked", **found[case], "case": case}), flush=True)
            if len(found) == len(targets):
                break
    el = time.perf_counter() - t0

    print(json.dumps({"event": "summary", "label": args.label, "elapsed_sec": round(el,1),
                      "candidates_tried": tried,
                      "rate_per_sec": round(tried/el, 2) if el else None,
                      "cracked": len(found), "total": len(targets)}, ensure_ascii=False))
    print("\n%-12s %-18s %-10s %s" % ("case", "tier", "结果", "命中口令/无"))
    for t in targets:
        f = found.get(t["case"])
        print("%-12s %-18s %-10s %s" % (t["case"], t["tier"],
              "**破解**" if f else "未命中",
              f["password"] if f else "-"))

if __name__ == "__main__":
    main()
