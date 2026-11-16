"""Systematic search for the avtab bucket function.

Constraints from real nodes (device): a node stored in bucket b satisfies
    bucket(key) == b   with bucket = H(pack(st, tt, tc, sp)) & 0x7fff
Seven samples, all with specified=1.  Rather than hand-decode the fused bfxil
mixer, enumerate a wide family of (packing, hash) pairs; a family member that
reproduces every sample is the kernel's function by construction.
"""
import itertools
import struct

M = 0xFFFFFFFF
SAMPLES = [
    (0, 311, 3543, 98, 1),
    (1, 1480, 2122, 8, 1),
    (2, 821, 1680, 14, 1),
    (3, 1588, 1622, 8, 1),
    (4, 1432, 2698, 11, 1),
    (5, 1398, 1207, 98, 1),
    (6, 1396, 2561, 10, 1),
]


def mul(a, b):
    return (a * b) & M


def ror(x, n):
    return ((x >> n) | ((x << (32 - n)) & M)) & M


def fmix32(h):
    h &= M
    h ^= h >> 16
    h = mul(h, 0x85EBCA6B)
    h ^= h >> 13
    h = mul(h, 0xC2B2AE35)
    h ^= h >> 16
    return h


def hash32_golden(x, bits=15):
    return (mul(x & M, 0x61C88647) >> (32 - bits)) & 0xFFFF


def jhash2(words, init=0):
    IV = (0xDEADBEEF + (len(words) << 2) + init) & M
    a = b = c = IV
    n = len(words)
    i = 0
    while n - i >= 3:
        a = (a + words[i]) & M
        b = (b + words[i + 1]) & M
        c = (c + words[i + 2]) & M
        # mix
        a = (a - c) & M
        a ^= ror(c, 4)
        c = (c + b) & M
        b = (b - a) & M
        b ^= ror(a, 6)
        a = (a + c) & M
        c = (c - b) & M
        c ^= ror(b, 8)
        b = (b + a) & M
        a = (a - c) & M
        a ^= ror(c, 16)
        c = (c + b) & M
        b = (b - a) & M
        b ^= ror(a, 19)
        a = (a + c) & M
        c = (c - b) & M
        c ^= ror(b, 4)
        b = (b + a) & M
        i += 3
    rest = n - i
    tail = 0
    for k in range(rest - 1, -1, -1):
        tail = (tail << 8) | (words[i + k] & 0xFF)
    if rest == 3:
        c = (c + words[i + 2]) & M
    if rest >= 2:
        b = (b + words[i + 1]) & M
    if rest >= 1:
        a = (a + words[i]) & M
    # final
    c ^= b
    c = (c - ror(b, 14)) & M
    a ^= c
    a = (a - ror(c, 11)) & M
    b ^= a
    b = (b - ror(a, 25)) & M
    c ^= b
    c = (c - ror(b, 16)) & M
    a ^= c
    a = (a - ror(c, 4)) & M
    b ^= a
    b = (b - ror(a, 14)) & M
    c ^= b
    c = (c - ror(b, 24)) & M
    return c


def pack32(vals, shifts):
    x = 0
    for v, s in zip(vals, shifts):
        x |= (v & 0xFFFF) << s
    return x & M


results = []
fields = ("st", "tt", "tc", "sp")
# 1) pack three fields then apply a 32-bit hash
for perm in itertools.permutations(range(4), 3):
    for shifts in itertools.permutations((0, 8, 16), 3):
        for hname, hf in (
            ("golden", hash32_golden),
            ("fmix", fmix32),
        ):
            ok = 0
            for b, st, tt, tc, sp in SAMPLES:
                vals = [st, tt, tc, sp]
                x = pack32([vals[i] for i in perm], shifts)
                if (hf(x) & 0x7FFF) == b or (hf(x) >> 17) == b:
                    ok += 1
            if ok >= 6:
                results.append((ok, f"{hname} perm={perm} shifts={shifts}"))
# 2) jhash2 over one or two 32-bit words
for perm in itertools.permutations(range(4), 2):
    for shifts in itertools.permutations((0, 16), 2):
        for nwords in (1, 2):
            ok = 0
            for b, st, tt, tc, sp in SAMPLES:
                vals = [st, tt, tc, sp]
                words = [pack32([vals[i] for i in perm], shifts)]
                if nwords == 2:
                    rest = [i for i in range(4) if i not in perm]
                    words.append(pack32([vals[i] for i in rest], (0, 16)))
                if (jhash2(words) & 0x7FFF) == b:
                    ok += 1
            if ok >= 6:
                results.append((ok, f"jhash2 perm={perm} shifts={shifts} n={nwords}"))

results.sort(reverse=True)
for ok, name in results[:15]:
    print(f"{ok}/7  {name}")
if not results:
    print("no candidate reached 6/7")
