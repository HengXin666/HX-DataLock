#!/usr/bin/env python3
"""把所有 CI/本机实测量汇成最终结论表。"""
import json

# 实测: 单次 scrypt 派生 (本机 32 物理核 / 62GB)
PER_GUESS_MS = {16384: 28.9, 262144: 549.0}     # Node @N=2^14 / Python @N=2^18
RATE_1CORE   = {16384: 34.6, 262144: 1.821}     # 次/秒
RATE_32CORE  = {16384: 34.6, 262144: 12.74}     # 次/秒 (实测加速仅 7.0x)

# CI 实测命中排名 (run 36313397366 / 36314748935)
HITS = [
    # case, 口令, 档, top10k纯, top100k纯, top10k+规则
    ("weak_01","123456",           "弱", 1,     0,     None),
    ("weak_02","password",         "弱", 0,     1,     None),
    ("weak_04","iloveyou",         "弱", 104,   49,    None),
    ("weak_05","admin123",         "弱", None,  15580, None),
    ("mid_01", "Password1",        "中", None,  3091,  2006),
    ("mid_02", "P@ssw0rd",         "中", None,  None,  None),
    ("mid_03", "Summer2024",       "中", None,  None,  None),
    ("mid_04", "iloveyou123",      "中", None,  None,  None),
    ("mid_05", "Woaini1314",       "中", None,  None,  None),
    ("mid_06", "Aa123456",         "中", None,  None,  None),
    ("strong_01","correct horse battery staple","强",None,None,None),
    ("strong_02","MyDogAteHomework2019!",      "强",None,None,None),
    ("bound_01", "Tz9#kLm4Qw2$Xp7Vn5Rb",       "上界",None,None,None),
]

def fmt(s):
    if s < 1: return f"{s*1000:.0f}ms"
    if s < 60: return f"{s:.1f}s"
    if s < 3600: return f"{s/60:.1f}min"
    if s < 86400: return f"{s/3600:.1f}h"
    return f"{s/86400:.1f}d"

print("="*96)
print("一、实测攻击吞吐 (scrypt 是内存硬, 加核不线性)")
print(f"  {'参数':<12}{'单次派生':>10}{'单核':>12}{'本机32核':>12}{'加速比':>9}   {'租1000台等价':>14}")
for N in (16384, 262144):
    sp = RATE_32CORE[N] / RATE_1CORE[N]
    print(f"  N=2^{N.bit_length()-1:<8d}{PER_GUESS_MS[N]:>8.1f}ms{RATE_1CORE[N]:>10.2f}/s{RATE_32CORE[N]:>10.2f}/s{sp:>8.1f}x{RATE_32CORE[N]*1000:>14.0f}/s")

print()
print("="*96)
print("二、命中排名 (字典深度 x 变形规则)")
print(f"  {'档':<5}{'口令':<28}{'top10k纯':>10}{'top100k纯':>11}{'top10k+规则':>13}")
for case, pw, tier, a, b, c in HITS:
    f = lambda v: str(v) if v is not None else "未命中"
    print(f"  {tier:<5}{pw:<28}{f(a):>10}{f(b):>11}{f(c):>13}")

print()
print("="*96)
print("三、换算成默认参数 (N=2^18) 下的真实攻破时间")
print(f"  {'档':<5}{'口令':<28}{'排名':>7}{'本机32核':>11}{'租1000台':>10}  判定")
for case, pw, tier, a, b, c in HITS:
    ranks = [v for v in (a, b, c) if v is not None]
    if not ranks:
        print(f"  {tier:<5}{pw:<28}{'-':>7}{'未命中':>11}{'-':>10}  在我的候选范围内存活")
        continue
    r = min(ranks)
    t = r / RATE_32CORE[262144]
    rented = r / (RATE_32CORE[262144] * 1000)
    verdict = "形同虚设" if t < 60 else ("脆弱" if t < 3600 else "勉强")
    print(f"  {tier:<5}{pw:<28}{r:>7}{fmt(t):>11}{fmt(rented):>10}  {verdict}")

print()
print("="*96)
print("四、三档结论")
print("  弱档: 全部在 top100k 内失守。最深的 admin123 在第 15580 位, 默认参数下本机 20 分钟、")
print("        租算力 1.2 秒。这档口令在本方案下没有任何保护。")
print("  中档: Password1 在第 2006-3091 位, 本机 2.6 分钟、租算力 0.16 秒。")
print("        P@ssw0rd / Aa123456 / Summer2024 / Woaini1314 未进入我的候选范围 —— 但这只")
print("        证明它们不在我抽样的这两份表里, 不证明它们安全。")
print("  强档: 口令短语与长随机串未被命中。")
print()
print("  关键: '未命中' 的上界取决于字典深度, 不是口令的性质。")
print("        admin123 在 top10k 下'未命中', 换 top100k 就落到第 15580 位。")
print()
print("="*96)
print("五、scrypt 为什么救不了弱口令")
print("  N 每翻一倍, 单次成本 x2, 但内存同样 x2。内存墙在 N=2^20 (每次 256MB)。")
print("  要再翻 4 倍到 2^24 需单次 4GB+, 不现实。")
print("  而字典深度的杠杆是免费的: 攻击者多下 10 倍大的表, 命中率就上一个台阶。")
print("  => 唯一有效变量是口令本身的熵, 也就是它是否落在字典里。")
