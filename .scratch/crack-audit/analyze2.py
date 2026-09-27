#!/usr/bin/env python3
"""用**实测**并行吞吐重算攻破成本。不再用理论核数。"""
import json

# 本机实测 (32 物理核, 62GB RAM)
MEASURED = {
    "single_core_per_sec_at_N18": 1.821,
    "parallel_32_per_sec_at_N18": 12.74,
    "speedup": 7.0,
}
CI_MS = {16384: 73.8, 262144: 586.8}

HITS = [
    ("weak_02", "password",  "弱", 0),
    ("weak_01", "123456",    "弱", 1),
    ("weak_04", "iloveyou",  "弱", 104),
    ("mid_01",  "Password1", "中", 2006),
]

RATE = MEASURED["parallel_32_per_sec_at_N18"]
print("="*80)
print("实测: 默认参数 N=2^18 下的攻击吞吐 (本机 32 核 / 62GB)")
print(f"  单核        {MEASURED['single_core_per_sec_at_N18']:.3f} 次/秒")
print(f"  32 核并行   {RATE:.2f} 次/秒  (加速仅 {MEASURED['speedup']}x, 理想 32x)")
print("  -> scrypt 是内存带宽瓶颈: 每次派生要摸 256MB, 32 并发需要 8GB 工作集")
print("  -> 加核的收益会在某个点完全饱和; 攻击者真正的杠杆是加内存通道与降低 N")

def fmt(s):
    if s < 1: return f"{s*1000:.0f}ms"
    if s < 60: return f"{s:.1f}s"
    if s < 3600: return f"{s/60:.1f}min"
    if s < 86400: return f"{s/3600:.1f}h"
    return f"{s/86400:.1f}d"

print()
print("="*80)
print("真实攻破时间 (默认参数, 本机 32 核实测吞吐)")
print(f"{'档':<4} {'口令':<12} {'字典排名':>8} {'本机32核':>10} {'单核':>10}")
for case, pw, tier, rank in HITS:
    print(f"{tier:<4} {pw:<12} {rank:>8} {fmt(rank/RATE):>10} {fmt(rank/MEASURED['single_core_per_sec_at_N18']):>10}")

print()
print("="*80)
print("对照: 攻击者的钱能买到什么")
print("  租 1000 台 32 核机 (约 $0.5/核/天 的云价, 一次性跑 1 天):")
print(f"    吞吐 ~ {RATE*1000:.0f} 次/秒 -> 一天可试 {RATE*1000*86400:.2e} 次")
print(f"    等价于字典深度 {RATE*1000*86400:.2e} 的口令")
print()
print("  => 用租算力硬推, 任何 <2^40 的口令空间都在一天内失守。")
print("     但真实用户口令不是均匀分布, 而是集中在泄露字典的前 10^4~10^6 名。")
print("     所以防御的着力点是让用户口令不落在字典里, 而不是把 KDF 调到内存墙。")

print()
print("="*80)
print("结论: 三档口令在这套方案下的实际安全等级")
for case, pw, tier, rank in HITS:
    t = rank / RATE
    verdict = "形同虚设" if t < 60 else ("脆弱" if t < 3600 else "勉强")
    print(f"  [{tier}] {pw:<12} 字典第 {rank:<5} 位  本机 {fmt(t):<9} -> {verdict}")
print()
print("  未被字典命中 ≠ 安全。未被命中只说明它不在我抽样的这份表里。")
