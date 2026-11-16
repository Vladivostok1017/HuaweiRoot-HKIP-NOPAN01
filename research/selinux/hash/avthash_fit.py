"""Fit SELinux avtab hash against real (bucket, key) samples from the device.

The bubble: avtab_search_node (0xffffffc0109d76ec) computes the bucket as
    bucket = mix(source_type, target_type, target_class) & mask
and the instruction stream is a murmur3/jhash-style mixer.  Rather than trust a
hand decoding, test candidate mixers against samples captured on-device: a node
stored in bucket i MUST hash to i.
"""
M = 0xFFFFFFFF


def mul(a, b):
    return (a * b) & M


def ror(x, n):
    return ((x >> n) | ((x << (32 - n)) & M)) & M


def bfxil(dst, src, lsb, width):
    mask = (((1 << width) - 1) << lsb) & M
    return ((dst & (~mask & M)) | (src & mask)) & M


def h_disasm(st, tt, tc):
    """Literal transcription of avtab_search_node's mixer."""
    c1 = 0xcc9e2d51
    c2 = 0x16a88000
    c3 = 0x1b873593
    c4 = 0xe6b26000
    c5 = 0xe6546b64
    c6 = 0x85ebca6b
    c7 = 0xc2b2ae35
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


def jhash3(a, b, c, init=0):
    """Standard jhash_3words(a,b,c,initval)."""
    IV = 0xDEADBEEF
    a = (a + IV + init) & M
    b = (b + IV + init) & M
    c = (c + IV + init) & M

    def mix(a, b, c):
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
        return a, b, c

    a, b, c = mix(a, b, c)
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


def hash32(val, bits):
    return mul(val, 0x61C88647) >> (32 - bits)


SAMPLES = [
    (1, 1480, 2122, 8),
    (2, 821, 1680, 14),
    (3, 1588, 1622, 8),
    (4, 1432, 2698, 11),
    (5, 1398, 1207, 98),
    (6, 1396, 2561, 10),
    (9, 820, 389, 6),
]
BITS = 15

cands = {
    "disasm(st,tt,tc)": lambda st, tt, tc: h_disasm(st, tt, tc),
    "jhash3(st,tt,tc)": lambda st, tt, tc: jhash3(st, tt, tc),
    "jhash3(tc,tt,st)": lambda st, tt, tc: jhash3(tc, tt, st),
    "jhash2(w0,w1)": lambda st, tt, tc: jhash3(st | (tt << 16), tc, 0),
    "hash32(st^(tt<<16)^(tc<<8))": lambda st, tt, tc: (hash32(st ^ (tt << 16) ^ (tc << 8), BITS) << (32 - BITS)) & M,
    "hash32(st|tt<<16|tc<<32 low32)": lambda st, tt, tc: (hash32((st | (tt << 16)) & M, BITS) << (32 - BITS)) & M,
}

for name, fn in cands.items():
    got = []
    ok = 0
    for bucket, st, tt, tc in SAMPLES:
        try:
            b = fn(st, tt, tc) & 0x7FFF
        except Exception as exc:  # noqa: BLE001
            b = f"err:{exc}"
        got.append(b)
        if b == bucket:
            ok += 1
    print(f"{name:34s} match {ok}/{len(SAMPLES)}  {got}")
