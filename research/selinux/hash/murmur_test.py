import struct
M = 0xFFFFFFFF
def mul(a,b): return (a*b) & M
def rol(x,n): return ((x<<n)|(x>>(32-n))) & M

def murmur3_32(data, seed=0):
    c1=0xcc9e2d51; c2=0x1b873593
    h=seed & M
    n=len(data)//4
    for i in range(n):
        k=int.from_bytes(data[i*4:(i+1)*4],'little')
        k=mul(k,c1); k=rol(k,15); k=mul(k,c2)
        h^=k; h=rol(h,13); h=(mul(h,5)+0xe6546b64)&M
    tail=data[n*4:]
    k=0
    if len(tail)>=3: k^=tail[2]<<16
    if len(tail)>=2: k^=tail[1]<<8
    if len(tail)>=1:
        k^=tail[0]; k=mul(k,c1); k=rol(k,15); k=mul(k,c2); h^=k
    h^=len(data)
    h^=h>>16; h=mul(h,0x85ebca6b); h^=h>>13; h=mul(h,0xc2b2ae35); h^=h>>16
    return h

S=[(0,311,3543,98,1),(1,1480,2122,8,1),(2,821,1680,14,1),(3,1588,1622,8,1),
   (4,1432,2698,11,1),(5,1398,1207,98,1),(6,1396,2561,10,1)]
def run(name, packer):
    ok=0; out=[]
    for b,st,tt,tc,sp in S:
        d=packer(st,tt,tc,sp)
        h=murmur3_32(d) & 0x7fff
        out.append(h)
        if h==b: ok+=1
    print(f"{name:28s} {ok}/7  {out}")
run("key8 LE (st,tt,tc,sp)", lambda st,tt,tc,sp: struct.pack('<4H',st,tt,tc,sp))
run("key8 (st,tt,sp,tc)", lambda st,tt,tc,sp: struct.pack('<4H',st,tt,sp,tc))
run("key4 (st,tt)", lambda st,tt,tc,sp: struct.pack('<2H',st,tt))
run("key4 (st,cls)", lambda st,tt,tc,sp: struct.pack('<2H',st,tc))
run("key8 BE", lambda st,tt,tc,sp: struct.pack('>4H',st,tt,tc,sp))
