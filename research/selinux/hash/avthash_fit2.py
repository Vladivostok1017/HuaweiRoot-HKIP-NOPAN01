"""Second-pass avtab hash fitter.

Samples are (bucket, source_type, target_type, target_class, specified) read
from real avtab nodes on the device.  A node stored in bucket i must hash to i,
so any candidate mixer that reproduces every sample is the one the kernel uses.

The point of trying a family is that the disassembly fuses jhash's rotate+mix
into `bfxil`, and a literal transcription of that fusion is easy to get subtly
wrong.  If a family member matches all samples, it is right by construction.
"""
M = 0xFFFFFFFF


def mul(a, b):
    return (a * b) & M


def ror(x, n):
    return ((x >> n) | ((x << (32 - n)) & M)) & M


def rol(x, n):
    return ((x << n) | (x >> (32 - n))) & M


def bfxil(dst, src, lsb, width):
    mask = (((1 << width) - 1) << lsb) & M
    return ((dst & (~mask & M)) | (src & mask)) & M


def jhash_mix(a, b, c):
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
    return a, b, c


def jhash_final(a, b, c):
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


def jhash3(a, b, c, init=0, use_mix=True):
    IV = (0xDEADBEEF + 12 + init) & M
    a = (a + IV) & M
    b = (b + IV) & M
    c = (c + IV) & M
    if use_mix:
        a, b, c = jhash_mix(a, b, c)
    return jhash_final(a, b, c)


def fmix32(h):
    h ^= h >> 16
    h = mul(h, 0x85EBCA6B)
    h ^= h >> 13
    h = mul(h, 0xC2B2AE35)
    h ^= h >> 16
    return h


def disasm(st, tt, tc, sp):
    c1 = 0xCC9E2D51
    c2 = 0x16A88000
    c3 = 0x1B873593
    c4 = 0xE6B26000
    c5 = 0xE6546B64
    c6 = 0x85EBCA6B
    c7 = 0xC2B2AE35
    w15 = mul(tc, c1)
    w16 = mul(tc, c2)
    w17 = mul(tt, c1)
    w16 = bfxil(w16, w15, 17, 15)
    w15b = mul(tt, c2)
    w15b = bfxil(w15b, w17, 17, 15)
    w12b = mul(st, c1)
    w13b = mul(st, c2)
    w13b = bfxil(w13b, w12b, 17, 15)
    t17 = mul(w16, c4)
    t16 = mul(w16, c3)
    t17 = bfxil(t17, t16, 19, 13)
    t17 = (t17 + ((t17 << 2) & M)) & M
    t17 = (t17 + c5) & M
    t15 = mul(w15b, c3)
    t15 = t17 ^ t15
    t15 = ror(t15, 19)
    t15 = (t15 + ((t15 << 2) & M)) & M
    t13 = mul(w13b, c3)
    t15 = (t15 + c5) & M
    t13 = t15 ^ t13
    t13 = ror(t13, 19)
    t13 = (t13 + ((t13 << 2) & M)) & M
    w12 = (t13 + c5) & M
    w12 ^= w12 >> 16
    w12 = mul(w12, c6)
    w12 ^= w12 >> 13
    w12 = mul(w12, c7)
    w12 ^= w12 >> 16
    return w12


CANDS = {
    "jhash3(st,tt,tc)": lambda st, tt, tc, sp: jhash3(st, tt, tc),
    "jhash3(st,tt,tc,noMix)": lambda st, tt, tc, sp: jhash3(st, tt, tc, use_mix=False),
    "jhash3(tc,tt,st)": lambda st, tt, tc, sp: jhash3(tc, tt, st),
    "jhash3(st|tt<<16,tc,sp)": lambda st, tt, tc, sp: jhash3(st | (tt << 16), tc, sp),
    "jhash3(st,tt,cls^spec)": lambda st, tt, tc, sp: jhash3(st, tt, tc ^ (sp << 8)),
    "fmix32(st^tt<<16)": lambda st, tt, tc, sp: fmix32((st ^ (tt << 16)) & M),
    "fmix32(st|tt<<16|tc<<8)": lambda st, tt, tc, sp: fmix32((st | (tt << 16) | (tc << 8)) & M),
    "fmix32(lor)": lambda st, tt, tc, sp: fmix32((st ^ rol(tt, 8) ^ rol(tc, 16)) & M),
    "disasm": lambda st, tt, tc, sp: disasm(st, tt, tc, sp),
}


def fit(samples, bits=15):
    mask = (1 << bits) - 1
    best = []
    for name, fn in CANDS.items():
        hits = sum(1 for b, st, tt, tc, sp in samples if (fn(st, tt, tc, sp) & mask) == b)
        best.append((hits, name))
    best.sort(reverse=True)
    for hits, name in best:
        print(f"{hits:3d}/{len(samples)}  {name}")


if __name__ == "__main__":
    # anchors confirmed twice on device (g51):
    samples = [
        (0, 311, 3543, 98, 1),
        (1, 1480, 2122, 8, 1),
        (2, 821, 1680, 14, 1),
        (3, 1588, 1622, 8, 1),
        (4, 1432, 2698, 11, 1),
        (5, 1398, 1207, 98, 1),
        (6, 1396, 2561, 10, 1),
    ]
    fit(samples)
    print("add more samples from status.txt: bucket:src/tgt/cls/spec")
