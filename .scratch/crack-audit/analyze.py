#!/usr/bin/env python3
"""把 CI 实测数据换算成"攻破成本"，并对照 scrypt 上限的杠杆。"""
import json

# CI 实测 (见 run 36313397366)
MS_PER_GUESS = {
    16384: 73.8,    # CI runner, Node, N=2^14
    262144: 586.8,  # CI runner, Node, N=2^18 (默认)
}
# 本机 32 核实测并行度 (scrypt 内存硬, 并行不线性)
LOCAL_PARALLEL_PER_SEC = {16384: 34.6, 262144: 1.94}

HITS = [
    ("weak_02", "password",   "弱", 0,    "纯字典"),
    ("weak_01", "123456",     "弱", 1,    "纯字典"),
    ("weak_04", "iloveyou",   "弱", 104,  "纯字典"),
    ("mid_01",  "Password1",  "中", 2006, "字典+变形"),
]

print("=" * 78)
print("实测: CI runner 单次 scrypt 派生耗时")
for k, v in MS_PER_GUESS.items():
    print(f"  N=2^{k.bit_length()-1:<2d} ({k:>7d})  {v:>7.1f} ms/次   {1000/v:>6.2f} 次/秒/核")
print(f"  比值 N=2^18 / N=2^14 = {MS_PER_GUESS[262144]/MS_PER_GUESS[16384]:.1f}x  (理论 16x)")

print()
print("=" * 78)
print("换算: 命中排名 -> 默认参数(N=2^18)下的攻破时间")
print(f"{'档':<4} {'口令':<26} {'排名':>6} {'单核':>12} {'32核':>12}  来源")
for case, pw, tier, rank, src in HITS:
    ms = MS_PER_GUESS[262144]
    serial = rank * ms / 1000
    par = serial / (LOCAL_PARALLEL_PER_SEC[262144] * 32 / 2.04)
    def fmt(s):
        if s < 1: return f"{s*1000:.0f}ms"
        if s < 60: return f"{s:.1f}s"
        if s < 3600: return f"{s/60:.1f}min"
        if s < 86400: return f"{s/3600:.1f}h"
        return f"{s/86400:.1f}d"
    print(f"{tier:<4} {pw:<26} {rank:>6} {fmt(serial):>12} {fmt(par):>12}  {src}")

print()
print("=" * 78)
print("scrypt 上限的杠杆: 若把 MAX_SCRYPT_N 从 2^20 提到 2^24")
print("  单次派生耗时 x16, 用同一排名换算:")
ms18 = MS_PER_GUESS[262144]
for case, pw, tier, rank, src in HITS:
    t20 = rank * ms18 * 4 / 1000 / 3600
    t24 = rank * ms18 * 64 / 1000 / 3600
    print(f"  {pw:<26} rank={rank:<6} N=2^18: {t20:>8.2f}h   N=2^24: {t24:>9.2f}h")
print()
print("  但 2^24 需要 256*N*r = 256*2^24*8 = 32 GiB 单次内存 —— 不现实。")
print("  这就是上限被卡在 2^20 的真正原因: 不是没想过, 是内存墙。")

print()
print("=" * 78)
print("关键结论: 字典深度 vs KDF 成本的杠杆比")
print("  1 个数量级的字典深度 = 10x 猜测量")
print("  1 个数量级的 scrypt N   = 10x 单次成本, 但内存同样 x10")
print("  攻击者用 GPU/ASIC 可以摊薄后者, 摊不薄前者 —— 所以口令熵才是主变量。")
