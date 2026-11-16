#!/usr/bin/env python3
"""
Static patch set that brings the HUAWEI NOP-AN01P (Mate 40 RS) Linux 5.10.43
Image up to userspace inside QEMU.

    Input : Image_nop_2026            raw arm64 Image, text_offset = 0
            vmlinux_nop_2026.elf      symbol source, _text = 0xffffffc010000000
    Output: Image_<profile>_patched

Fact used everywhere: file offset == (symbol vaddr - _text), because the arm64
Image header of this build carries text_offset = 0.  Verified on is_cma_pfn
(symbol 0xffffffc010469d70 -> file 0x469d70 shows the expected prologue); every
fixed-offset patch below asserts its original bytes and fails loudly on a
mismatch instead of corrupting the image.

Boot profiles:

  plain  QEMU generated DT, "-M virt" (no secure=on).  Needs the
         __arm_smccc_smc patch; Huawei's pmalloc has no pool node here, so
         selinux_protection_init is skipped as well.

  dtb    real Huawei DT (nop_qemu2.dtb) + "-M virt,gic-version=3,secure=on,
         virtualization=on": secure=on makes vendor SMCs trap and return
         NOT_SUPPORTED.  Huawei's pmalloc still needs a pool node that the
         cleared reserved-memory no longer provides, so selinux_protection_init
         is skipped here too (kept explicit in the table).

usage:  python patch_kernel.py [--profile plain|dtb] [--list]
"""

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "Image_nop_2026")

MOV_W0_WZR = 0x2A1F03E0   # mov w0, wzr
MOV_X0_XZR = 0xAA1F03E0   # mov x0, xzr
RET = 0xD65F03C0          # ret
NOP = 0xD503201F          # nop
BRK_800 = 0xD4210000      # brk #0x800
ALL_PROFILES = ("plain", "dtb")


def enc(*words):
    return b"".join(struct.pack("<I", w) for w in words)


# ---------------------------------------------------------------------------
# fixed-offset patches
#   name, file offset, original bytes, replacement bytes, profiles, rationale
# ---------------------------------------------------------------------------
PATCHES = [
    (
        "is_cma_pfn",
        0x469D70,
        bytes.fromhex("88d101b008c140f9"),
        enc(MOV_W0_WZR, RET),
        ALL_PROFILES,
        "Vendor CMA predicate: `adrp x8,#0xffffffc013e9a000; ldr x8,[x8,#0x180]; "
        "ldr x9,[x8]`. The global at +0x180 is only initialised by Huawei's "
        "bootloader, so memmap_init_zone_range() faults on NULL before the "
        "console is up. Forcing the predicate false is safe: it only classifies "
        "PFNs.",
    ),
    (
        "__arm_smccc_smc",
        0x3E00,
        bytes.fromhex("030000d4"),
        enc(MOV_X0_XZR),
        ("plain",),
        "Generic SMC wrapper: `smc #0; ldr x4,[sp]; stp x0,x1,[x4]; "
        "stp x2,x3,[x4,#0x10]`. Without EL3 the SMC is an undefined instruction "
        "and Huawei's rand_initialize/hkip issue vendor SMCs (0xc3004800) "
        "through here. `mov x0,xzr` keeps the result store; every SMC then "
        "returns zeros. Not needed in the dtb profile (secure=on answers the "
        "SMC). PSCI is unaffected: the virt DT advertises method=\"hvc\" and the "
        "kernel uses __arm_smccc_hvc for it.",
    ),
    (
        "selinux_protection_init",
        0x3334954,
        bytes.fromhex("fd7bbea9"),
        enc(RET),
        ALL_PROFILES,
        "`bl pmalloc_aligned; str x0,[x19,#8]; cbz x0 -> pr_err + brk`. Huawei's "
        "pmalloc pool comes from the DT `physical-memory-group-manager` node; "
        "without a working pool grow()/pool_add_node() hits `kernel BUG at "
        "prmem.c:635`. Skipping the allocation leaves the field NULL, which is "
        "tolerated (the first consumer that is not tolerated shows up as its "
        "own crash site).",
    ),
    (
        "hkip_init_task",
        0x2203118,
        bytes.fromhex("fd7bbda9f65701a9"),
        enc(MOV_W0_WZR, RET),
        ALL_PROFILES,
        "HKIP per-task init from copy_process(); it calls into Huawei's "
        "hypervisor and BUGs when the secure side is absent, which kills "
        "rest_init() -> kernel_init before userspace exists.",
    ),
    (
        "hkip_check_xid_root",
        0x2202EA0,
        bytes.fromhex("fd7bbfa9fd030091"),
        enc(MOV_W0_WZR, RET),
        ALL_PROFILES,
        "HKIP gate from copy_process(): asks the hypervisor whether a task may "
        "hold a root xid and BUGs without it (critdata.c:156). Return 0 = "
        "allowed.",
    ),
    (
        "hkip_check_uid_root",
        0x2202FD0,
        bytes.fromhex("fd7bbfa9fd030091"),
        enc(MOV_W0_WZR, RET),
        ALL_PROFILES,
        "Same HKIP root-uid gate.",
    ),
    (
        "hkip_check_gid_root",
        0x2203070,
        bytes.fromhex("fd7bbfa9fd030091"),
        enc(MOV_W0_WZR, RET),
        ALL_PROFILES,
        "Same HKIP root-gid gate.",
    ),
    (
        "cfi_harden_init",
        0x220A850,
        bytes.fromhex("fd7bbfa9fd030091"),
        enc(MOV_W0_WZR, RET),
        ALL_PROFILES,
        "kernel_init_freeable() -> cfi_harden_init() -> prmem_cache_preload() "
        "-> pmalloc -> grow -> pool_add_node -> `kernel BUG at "
        "platform_source/see/drivers/prmem/prmem.c:635`. Skipping the preload "
        "only weakens Huawei's own CFI hardening.",
    ),
]


# ---------------------------------------------------------------------------
# Pattern patch: Huawei's anti-escalation asserts.
#
# Every variant shares the shape
#       add  x0, x0, #<string offset>     ; adrp x0,<page> immediately before
#       bl   printk
#       brk  #0x800
# and is reached by *branches* from the surrounding function, e.g. cap_capable
# does `ldr w9,[cred,#4]; cbz w9, <assert>` for uid/euid/suid/fsuid==0 and for
# non-empty cap_inheritable/cap_permitted.  Since PID 1 runs as root it always
# takes one of those branches, so the assert fires during boot.
#
# NOPing the brk is wrong: several of these blocks sit after a `ret` and fall
# through into unrelated code (we hit an ARMv8.4 LDAPRB that way).  The correct
# fix is to NOP the *branches that target the assert block*, which makes the
# function continue into its normal permission logic.
# ---------------------------------------------------------------------------
def find_assert_sites(img):
    """Offsets of the `add x0,x0,#imm` that start each assert block."""
    sites = []
    for i in range(0, len(img) - 12, 4):
        w_add = struct.unpack_from("<I", img, i)[0]
        w_bl = struct.unpack_from("<I", img, i + 4)[0]
        w_brk = struct.unpack_from("<I", img, i + 8)[0]
        if w_brk != BRK_800:
            continue
        if (w_bl >> 26) != 0x25:                       # bl
            continue
        if (w_add & 0xFFC00000) != 0x91000000:         # add (imm, 64-bit)
            continue
        if ((w_add >> 5) & 0x1F) != 0 or (w_add & 0x1F) != 0:
            continue                                   # must be x0, x0, #imm
        # The add must point at the exact string Huawei uses for this assert
        # ("UID root escalation!"): that is what distinguishes these 8 inlined
        # copies from the 3000+ ordinary pr_err()+BUG() sites in their tree.
        if ((w_add >> 10) & 0xFFF) != 0x676:
            continue
        sites.append(i)
    return sites


def branch_target(w, pc):
    """Target of B/B.cond/CBZ/CBNZ/TBZ/TBNZ, else None."""
    if (w & 0xFC000000) == 0x14000000:                 # b
        imm = w & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        return pc + imm * 4
    if (w & 0xFF000010) == 0x54000000:                 # b.cond
        imm = (w >> 5) & 0x7FFFF
        if imm & 0x40000:
            imm -= 0x80000
        return pc + imm * 4
    if (w & 0x7E000000) == 0x34000000:                 # cbz / cbnz
        imm = (w >> 5) & 0x7FFFF
        if imm & 0x40000:
            imm -= 0x80000
        return pc + imm * 4
    if (w & 0x7E000000) == 0x36000000:                 # tbz / tbnz
        imm = (w >> 5) & 0x3FFF
        if imm & 0x2000:
            imm -= 0x4000
        return pc + imm * 4
    return None


def kill_assert_branches(img, verbose):
    sites = set(find_assert_sites(img))
    if not sites:
        print("FATAL: no Huawei anti-escalation assert blocks found",
              file=sys.stderr)
        return False
    killed = 0
    for i in range(0, len(img) - 4, 4):
        w = struct.unpack_from("<I", img, i)[0]
        t = branch_target(w, i)
        if t in sites:
            img[i:i + 4] = struct.pack("<I", NOP)
            killed += 1
            if verbose:
                print(f"[assert] nop branch @0x{i:06x} -> assert 0x{t:06x}")
    print(f"[assert] {len(sites)} assert blocks, {killed} branches nop'ed")
    return killed > 0


def build(profile, out_path):
    with open(SRC, "rb") as fh:
        img = bytearray(fh.read())
    applied = 0

    for name, off, orig, new, profiles, why in PATCHES:
        if profile not in profiles:
            continue
        cur = bytes(img[off:off + len(orig)])
        if cur != orig:
            print(f"FATAL[{profile}] {name} @0x{off:x}: expected {orig.hex()}, "
                  f"found {cur.hex()}", file=sys.stderr)
            return False
        img[off:off + len(new)] = new
        applied += 1
        print(f"[{profile}] {name:32s} @0x{off:06x} {orig.hex()} -> {new.hex()}")

    if not kill_assert_branches(img, verbose=("-v" in sys.argv)):
        return False

    with open(out_path, "wb") as fh:
        fh.write(img)
    print(f"[{profile}] {applied} fixed patches -> {out_path} "
          f"({len(img)} bytes)")
    return True


def main(argv):
    if "--list" in argv:
        for name, off, orig, new, profiles, why in PATCHES:
            print(f"{name} @0x{off:06x} {orig.hex()} -> {new.hex()}  "
                  f"[{','.join(profiles)}]\n    {why}")
        print("plus: NOP every branch that targets a Huawei "
              "'add x0,x0,#imm; bl printk; brk #0x800' assert block")
        return 0
    profiles = ALL_PROFILES
    if "--profile" in argv:
        profiles = (argv[argv.index("--profile") + 1],)
    ok = True
    for prof in profiles:
        ok &= build(prof, os.path.join(HERE, f"Image_{prof}_patched"))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
