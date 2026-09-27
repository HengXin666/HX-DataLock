#!/usr/bin/env python3
"""测量攻击者真实吞吐: 单核/多核, Python 与 Node 两条路径。"""
from __future__ import annotations
import base64, json, os, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, "/home/hx/Loli/code/HXLoLis/utils/HX-DataLock/sdk/py/src")

TARGET = Path("/home/hx/Loli/code/HXLoLis/utils/HX-DataLock/.scratch/crack-audit/targets/weak_02_N262144.json")
kr = json.loads(TARGET.read_text())
enc, key_id = kr["encryptedReadKey"], kr["publicWriteKey"]["keyId"]

sys.path.insert(0, "/home/hx/Loli/code/HXLoLis/utils/HX-DataLock/.scratch/crack-audit")
from hxdl_crack import try_password

for N in (16384, 65536, 262144, 1048576):
    e = dict(enc); e["kdf"] = dict(enc["kdf"], N=N)
    t = time.perf_counter()
    try_password("__bench__", e, key_id)
    d = time.perf_counter() - t
    print(json.dumps({"kdf_N": N, "seconds_per_guess": round(d, 3),
                      "guesses_per_sec_1core": round(1/d, 2),
                      "guesses_per_day_1core": int(86400/d)}))
print(json.dumps({"cpu_count": os.cpu_count()}))

# 多核实测
from concurrent.futures import ProcessPoolExecutor
words = [f"bench{i}" for i in range(64)]
def w(chunk):
    return sum(1 for x in chunk if try_password(x, enc, key_id))
t = time.perf_counter()
with ProcessPoolExecutor(max_workers=os.cpu_count()) as p:
    list(p.map(w, [words[i:i+1] for i in range(len(words))]))
el = time.perf_counter() - t
print(json.dumps({"parallel_guesses_per_sec": round(len(words)/el, 1), "cores": os.cpu_count()}))
