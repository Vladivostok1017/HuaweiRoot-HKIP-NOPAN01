#!/usr/bin/env python3
"""kimage.py — 从 vmlinux 里查符号、把地址翻回符号、按符号反汇编、读内嵌数据。

本仓库所有 `0x…` 偏移都是这样从设备 vmlinux 得到的，不是猜的。

    python kimage.py --elf vmlinux.elf sym hkip_check_uid_root avc_has_perm
    python kimage.py --elf vmlinux.elf at  0xffffffc0109da654
    python kimage.py --elf vmlinux.elf dis hkip_check_uid_root
    python kimage.py --elf vmlinux.elf dis 0xffffffc0102202fd0 0x60
    python kimage.py --elf vmlinux.elf q   0xffffffc013e9a180
    python kimage.py --elf vmlinux.elf u32 0xffffffc0109da654

`--elf` 省略时取 $KIMAGE，再退到当前目录的 vmlinux.elf。

约定：本机 Image 头里 text_offset = 0，所以
    文件偏移 == (符号虚拟地址 - _text)
这一点在 `sym` 输出里直接给出（`off`），用来给 patch_kernel.py 的定址补丁喂偏移。
"""
import argparse
import bisect
import os
import struct
import sys

BASE_DEFAULT = 0xFFFFFFC010000000   # _text of the NOP-AN01P 5.10.43 build


class KImage:
    def __init__(self, path):
        self.f = open(path, 'rb')
        self.path = path
        self.sections = []           # (name, type, flags, addr, off, size)
        self._load_sections()
        self.syms = []               # (value, name, size) sorted by value
        self.addrs = []
        self._load_symbols()

    # ---- ELF 结构 ----
    def _load_sections(self):
        f = self.f
        hdr = f.read(64)
        if hdr[:4] not in (b'\x7fELF',) or hdr[4] != 2 or hdr[5] != 1:
            raise SystemExit('%s: not a little-endian ELF64' % self.path)
        e_shoff, = struct.unpack_from('<Q', hdr, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', hdr, 0x3a)
        f.seek(e_shoff)
        raw = f.read(e_shentsize * e_shnum)
        tmp = []
        for i in range(e_shnum):
            o = i * e_shentsize
            nameoff, typ, flags, addr, off, size, link, info, align, entsize = \
                struct.unpack_from('<IIQQQQIIQQ', raw, o)
            tmp.append((nameoff, typ, flags, addr, off, size))
        strtab_off, strtab_size = tmp[e_shstrndx][4], tmp[e_shstrndx][5]
        f.seek(strtab_off)
        shstr = f.read(strtab_size)
        for nameoff, typ, flags, addr, off, size in tmp:
            end = shstr.index(b'\0', nameoff)
            name = shstr[nameoff:end].decode('utf-8', 'replace')
            self.sections.append((name, typ, flags, addr, off, size))

    def _load_symbols(self):
        f = self.f
        symtab = next((s for s in self.sections if s[0] == '.symtab'), None)
        strtab = next((s for s in self.sections if s[0] == '.strtab'), None)
        if symtab is None or strtab is None:
            raise SystemExit('%s: no .symtab/.strtab (stripped image?)' % self.path)
        f.seek(strtab[4])
        names = f.read(strtab[5])
        f.seek(symtab[4])
        data = f.read(symtab[5])
        out = []
        for i in range(len(data) // 24):
            nameoff, info, other, shndx, value, size = struct.unpack_from(
                '<IBBHQQ', data, i * 24)
            if nameoff == 0 or value == 0:
                continue
            end = names.index(b'\0', nameoff)
            nm = names[nameoff:end].decode('utf-8', 'replace')
            out.append((value, nm, size))
        out.sort()
        self.syms = out
        self.addrs = [s[0] for s in out]

    # ---- 地址 → 文件 ----
    def read(self, addr, n):
        """addr 是链接期虚拟地址；按所属 section 映射到文件字节。"""
        for name, typ, flags, saddr, off, size in self.sections:
            if typ == 8:                       # SHT_NOBITS (.bss)：文件里没有
                continue
            if saddr and saddr <= addr < saddr + size:
                self.f.seek(off + (addr - saddr))
                return self.f.read(n)
        raise SystemExit('%#x: not in any file-backed section (.bss, or not a kernel address)' % addr)

    def u64(self, addr):
        return struct.unpack('<Q', self.read(addr, 8))[0]

    def u32(self, addr):
        return struct.unpack('<I', self.read(addr, 4))[0]


def find_syms(img, want):
    hits = [s for s in img.syms if s[1] == want]
    if hits:
        return hits, False
    return [s for s in img.syms if want in s[1]][:10], True


def cmd_sym(img, names, base):
    for w in names:
        hits, fuzzy = find_syms(img, w)
        if not hits:
            print('%s  <not found>' % w)
            continue
        for value, nm, size in hits:
            print('%s%s  addr %#x  off %#x  size %s' % (
                '~ ' if fuzzy else '= ', nm, value, value - base,
                hex(size) if size else '?'))
    return 0


def cmd_at(img, addrs):
    for a in addrs:
        t = int(a, 16)
        i = bisect.bisect_right(img.addrs, t) - 1
        if i < 0:
            print('%#x  <none>' % t)
            continue
        v, nm, sz = img.syms[i]
        exact = (t == v) or (sz and t - v < sz)
        fuzzy = '' if exact else '  (~ nearest symbol, address not proven inside it)'
        print('%#x  ->  %s + %#x   (sym %#x size %s)%s' % (
            t, nm, t - v, v, hex(sz) if sz else '?', fuzzy))
    return 0


def cmd_dis(img, target, length, base):
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    except ImportError:
        print('needs capstone: pip install capstone', file=sys.stderr)
        return 2
    if target.lower().startswith('0x'):
        start = int(target, 16)
        name = '0x%x' % start
    else:
        hits, _ = find_syms(img, target)
        if not hits:
            print('%s  <not found>' % target, file=sys.stderr)
            return 2
        start, name, size = hits[0]
        if length is None and size:
            length = size
    if length is None:
        length = 0x80
    code = img.read(start, length)
    print('=== %s @ %#x (off %#x, %d bytes) ===' % (name, start, start - base, len(code)))
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for ins in md.disasm(code, start):
        print('  %#010x  %-8s %s' % (ins.address, ins.mnemonic, ins.op_str))
    return 0


def cmd_q(img, addrs, width):
    for a in addrs:
        x = int(a, 16)
        print('%#x  ->  %#x' % (x, img.u64(x) if width == 8 else img.u32(x)))
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--elf', default=os.environ.get('KIMAGE', 'vmlinux.elf'))
    ap.add_argument('--base', default=hex(BASE_DEFAULT))
    ap.add_argument('cmd', choices=['sym', 'at', 'dis', 'q', 'u32'])
    ap.add_argument('args', nargs='*')
    ns = ap.parse_args(argv)
    if not os.path.exists(ns.elf):
        raise SystemExit('cannot open %s: pass --elf or set $KIMAGE' % ns.elf)
    base = int(ns.base, 16)
    img = KImage(ns.elf)
    print('# %s  %d symbols  base %#x' % (ns.elf, len(img.syms), base), file=sys.stderr)
    if ns.cmd == 'sym':
        return cmd_sym(img, ns.args, base)
    if ns.cmd == 'at':
        return cmd_at(img, ns.args)
    if ns.cmd == 'dis':
        if not ns.args:
            raise SystemExit('dis needs a symbol name or an address')
        length = int(ns.args[1], 16) if len(ns.args) > 1 else None
        return cmd_dis(img, ns.args[0], length, base)
    if ns.cmd == 'q':
        return cmd_q(img, ns.args, 8)
    if ns.cmd == 'u32':
        return cmd_q(img, ns.args, 4)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
