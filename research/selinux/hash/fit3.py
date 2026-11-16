M = 0xFFFFFFFF
def mul(a,b): return (a*b) & M
def ror(x,n): return ((x>>n)|((x<<(32-n))&M)) & M
def bfxil(dst, src, lsb, width):
    # ARM BFXIL Wd,Wn,#lsb,#width : Wd[width-1:0] = Wn[lsb+width-1:lsb]
    fmask = (1<<width)-1
    field = (src >> lsb) & fmask
    return ((dst & (~fmask & M)) | field) & M

def H(st,tt,tc):
    c1=0xcc9e2d51; c2=0x16a88000; c3=0x1b873593; c4=0xe6b26000
    c5=0xe6546b64; c6=0x85ebca6b; c7=0xc2b2ae35
    w15 = mul(tc,c1); w16 = mul(tc,c2); w17 = mul(tt,c1)
    w16 = bfxil(w16,w15,17,15)
    w15 = mul(tt,c2); w15 = bfxil(w15,w17,17,15)
    w12 = mul(st,c1); w13 = mul(st,c2); w13 = bfxil(w13,w12,17,15)
    t17 = mul(w16,c4); t16 = mul(w16,c3)
    t17 = bfxil(t17,t16,19,13)
    t17 = (t17 + ((t17<<2)&M)) & M
    t17 = (t17 + c5) & M
    t15 = mul(w15,c3)
    t15 = t17 ^ t15
    t15 = ror(t15,19)
    t15 = (t15 + ((t15<<2)&M)) & M
    t13 = mul(w13,c3)
    t15 = (t15 + c5) & M
    t13 = t15 ^ t13
    t13 = ror(t13,19)
    t13 = (t13 + ((t13<<2)&M)) & M
    w12 = (t13 + c5) & M
    w12 ^= w12>>16
    w12 = mul(w12,c6)
    w12 ^= w12>>13
    w12 = mul(w12,c7)
    w12 ^= w12>>16
    return w12

S=[(0,311,3543,98),(1,1480,2122,8),(2,821,1680,14),(3,1588,1622,8),
   (4,1432,2698,11),(5,1398,1207,98),(6,1396,2561,10),(0,821,2867,192)]
ok=0
for b,st,tt,tc in S:
    h=H(st,tt,tc); bb=h & 0x7fff
    print(f"{st}/{tt}/{tc} -> {bb} (expect {b})")
    if bb==b: ok+=1
print("match", ok, "/", len(S))
