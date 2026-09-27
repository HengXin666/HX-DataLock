#!/usr/bin/env python3
"""离线爆破 (v2): 按目标并行, 命中即停, 记录命中排名。

排名与 scrypt 参数无关 (同一字典同一顺序), 所以低 N 测出的排名可直接
换算到默认 N 下的真实耗时。
"""
from __future__ import annotations
import argparse, base64, json, os, sys, time, unicodedata
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, "/home/hx/Loli/code/HXLoLis/utils/HX-DataLock/sdk/py/src")
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SCHEMA = "hxdl.keyring.v1"
_T = None

def _init(t):
    global _T
    _T = t

def check(pw, enc, key_id):
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

def _scan(chunk):
    for pw in chunk:
        if check(pw, _T["enc"], _T["key_id"]):
            return pw
    return None

def build_candidates(path, limit, rules):
    base = [w.rstrip("\n") for w in Path(path).read_text(encoding="utf-8", errors="replace").splitlines()]
    base = [w for w in base if w and len(w) < 48]
    if limit: base = base[:limit]
    cands = list(base)
    if rules:
        extra = []
        for w in base[:8000]:
            c = w.capitalize()
            for s in ("1","12","123","1234","!","@","#","2024","2025","2026","1990","1966","888","520","1314"):
                extra.append(w+s); extra.append(c+s)
            extra.append(w.upper())
        cands = list(dict.fromkeys(cands + extra))
    return cands

def crack_target(t, cands, jobs):
    global _T
    _T = t
    CH = 16
    chunks = [cands[i:i+CH] for i in range(0, len(cands), CH)]
    tried = 0
    t0 = time.perf_counter()
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        for res in pool.map(_scan, chunks, chunksize=1):
            tried += CH
            if res:
                return {"found": True, "password": res, "rank": tried,
                        "elapsed_sec": round(time.perf_counter()-t0, 2)}
    return {"found": False, "password": None, "rank": None,
            "elapsed_sec": round(time.perf_counter()-t0, 2)}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wordlist", required=True)
    ap.add_argument("--targets", required=True)
    ap.add_argument("--jobs", type=int, default=28)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--rules", action="store_true")
    ap.add_argument("--only", default="")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    idx = json.loads(Path(args.targets).read_text(encoding="utf-8"))
    if args.only:
        keep = set(args.only.split(","))
        idx = [e for e in idx if e["case"] in keep]
    cands = build_candidates(args.wordlist, args.limit, args.rules)
    N = None
    t0 = time.perf_counter()
    results = []
    for e in idx:
        kr = json.loads(Path(e["keyring"]).read_text(encoding="utf-8"))
        t = {"case": e["case"], "tier": e["tier"], "pw_true": e["password"],
             "enc": kr["encryptedReadKey"], "key_id": kr["publicWriteKey"]["keyId"]}
        N = t["enc"]["kdf"]["N"]
        r = crack_target(t, cands, args.jobs)
        r.update({"case": e["case"], "tier": e["tier"]})
        results.append(r)
        print(json.dumps({"event":"target", **r,
                          "correct": r["password"] == e["password"] if r["found"] else None},
                         ensure_ascii=False), flush=True)

    el = time.perf_counter() - t0
    Path(args.out).write_text(json.dumps(
        {"scrypt_N": N, "candidates": len(cands), "jobs": args.jobs,
         "total_elapsed_sec": round(el,1), "results": results}, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n%-11s %-16s %-9s %-16s %s" % ("case","tier","结果","命中排名","口令"))
    for r in results:
        print("%-11s %-16s %-9s %-16s %s" % (r["case"], r["tier"],
              "**破解**" if r["found"] else "未命中",
              str(r["rank"]) if r["rank"] else "-",
              r["password"] if r["found"] else "-"))
    hit = sum(1 for r in results if r["found"])
    print(f"\n命中 {hit}/{len(results)}  N={N}  候选={len(cands)}  总耗时={el:.0f}s")

if __name__ == "__main__":
    main()
