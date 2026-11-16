# qemu

把这台机器的内核 Image 补到能在 QEMU 里跑到用户态。

意义不在于"跑个虚拟机"，在于**离线验证**：改一个 HKIP gate、改一处策略保护，不用打洞、不用重启真机，
直接在 QEMU 里看它会不会 BUG。本仓库大部分指令级结论都是先在这里对过一遍的。

```bash
cp /path/to/Image_nop_2026 .              # 设备 boot 分区里的 raw arm64 Image（不随仓库分发）
python patch_kernel.py --list            # 打印补丁表
python patch_kernel.py --profile plain   # QEMU 自带 DT，无 secure
python patch_kernel.py --profile dtb     # 真实华为 DT + secure=on
```

产物 `Image_<profile>_patched`。每个补丁都**先断言原始字节**再改，字节不符就报错退出——不会静默毁掉镜像。

## 为什么能这样定址

这个构建的 arm64 Image 头里 `text_offset = 0`，所以

```
文件偏移 == (符号虚拟地址 - _text)，_text = 0xffffffc010000000
```

这条在 `is_cma_pfn` 上验证过（符号 `0xffffffc010469d70` → 文件 `0x469d70` 处正是预期序言）。

## 两个 profile 的差别

| | `plain` | `dtb` |
|---|---|---|
| 设备树 | QEMU 生成，`-M virt` | 真实华为 DT，`-M virt,gic-version=3,secure=on,virtualization=on` |
| SMC | 需要打掉 `__arm_smccc_smc`（无 EL3，`smc #0` 是未定义指令） | 不需要（`secure=on` 让厂商 SMC 陷入并返回 NOT_SUPPORTED） |
| pmalloc 池 | 没有池节点，`selinux_protection_init` / `cfi_harden_init` 都要跳过 | 同样没有（清过 reserved-memory），同样跳过 |

## 补丁表

| 符号 | off | 原始 → 改后 | 为什么 |
|---|---|---|---|
| `is_cma_pfn` | `0x469d70` | `88d101b0 08c140f9` → `e0031f2a c0035fd6` | 谓词读全局 `+0x180`，那个值只有华为 bootloader 设过；不设则 `memmap_init_zone_range()` 在 console 起来前就空指针 |
| `__arm_smccc_smc` | `0x003e00` | `030000d4` → `e0031faa` | 无 EL3 时 `smc #0` 未定义；`mov x0,xzr` 保住结果存储，SMC 全部返回 0（PSCI 走 `__arm_smccc_hvc`，不受影响） |
| `selinux_protection_init` | `0x3334954` | `fd7bbea9` → `c0035fd6` | pmalloc 需要 DT 里的 `physical-memory-group-manager` 节点；没有它 `grow()/pool_add_node()` 直接 `kernel BUG at prmem.c:635` |
| `hkip_init_task` | `0x2203118` | `fd7bbda9 f65701a9` → `e0031f2a c0035fd6` | `copy_process` 里调 EL2，secure 侧不在就 BUG，直接杀掉 `rest_init() → kernel_init` |
| `hkip_check_xid_root` | `0x2202ea0` | `fd7bbfa9 fd030091` → `e0031f2a c0035fd6` | 问 hypervisor 能不能持有 root xid，答不上来就 BUG（`critdata.c:156`）；返回 0 = 放行 |
| `hkip_check_uid_root` | `0x2202fd0` | 同上 | 同族 uid gate |
| `hkip_check_gid_root` | `0x2203070` | 同上 | 同族 gid gate |
| `cfi_harden_init` | `0x220a850` | 同上 | `prmem_cache_preload → pmalloc → grow → pool_add_node`，同样的 `prmem.c:635`；跳过只削弱华为自家的 CFI |

除此之外还会把**所有指向**华为断言块的跳转 NOP 掉——那些块的形状是
`add x0, x0, #imm; bl printk; brk #0x800`（打印一行然后复位设备）。
真机上见到的 `brk #0x800` 复位就是这些块干的，`docs/01-hkip.md` 里有对应记录。
