# research

这一层不是"怎么拿到 root"，是**这台机器本身**的研究：

内核被编译成什么样、镜像由什么组成、EL2 那层保护在哪些指令上做判断、SELinux 策略体在内存里长什么形状。

材料来源统一——设备自己的 vmlinux（213,390 条符号）、设备的内核配置、以及运行时的实测读数。
仓库不收 vmlinux / Image / dump 本体（体积从几十 MB 到 750 MB），收的是从中提炼出的结论，以及重新取它的工具。

| 目录 | 回答什么问题 |
|---|---|
| `system/` | 这台机器的内核编译成了什么样。`kernel-config.txt` 是完整 Kconfig：能看到 Huawei 自加的 HKIP / prmem / CFI 段落，也能看到被关掉的东西（`# CONFIG_KPROBES is not set`、`MODULE_SIG_FORCE=y`、`CONFIG_SECURITY_SELINUX_DEVELOP` 未开） |
| `qemu/` | 这套内核能不能脱离真机跑起来。答案能：一份**逐条定址的静态补丁表**，把 Image 补到 QEMU 里跑到用户态 |
| `hkip/` | HKIP/HHEE 在哪几条指令上拦人：`copy_process`/`prepare_creds` 侧的四个 gate 反汇编、切换上下文的现场、以及"能不能拿 ROP 绕过去"的推演 |
| `selinux/` | 策略体在内存里的形状：avtab 布局、桶哈希（已能自己算）、AVC 缓存为什么打不动 |
| `init-domain/` | init 域究竟能做什么，为什么"把进程变成 init 域"不能当常驻形态 |
| `tooling/` | 从 vmlinux 取符号、翻地址、反汇编、读内嵌数据 |
| `reports/` | 三轮完整记录：总报告、上游踩过的坑、与上游分支的逐项差异核对 |
| `notes/` | 时间点笔记。`soft-reboot-hook.md`：门在软重启（`restart zygote`）中存活，于是有了一个可自己触发、时机可控的"准开机窗口" |

## 关键数字

全部可以从 `tooling/kimage.py` 复核；偏移是相对 `_text = 0xffffffc010000000`。

| 符号 | off | 是什么 |
|---|---|---|
| `__arm_smccc_smc` | `0x003e00` | 通用 SMC 包装；在无 EL3 的 QEMU 里必须打掉 |
| `is_cma_pfn` | `0x469d70` | Huawei 的 CMA 谓词，依赖 bootloader 初始化的全局 |
| `__switch_to` | `0x8d818` | 上下文切换现场（HKIP 关心的是 `sp_el0` 指向谁） |
| `avc_has_perm` | `0x9bf778` | AVC 判定入口 |
| `security_compute_av` | `0x9da654` | 策略查询入口 |
| `hkip_check_xid_root` | `0x2202ea0` | `copy_process` 侧的 xid gate |
| `hkip_check_uid_root` | `0x2202fd0` | `copy_process` 侧的 uid gate |
| `hkip_check_gid_root` | `0x2203070` | 同族的 gid gate |
| `hkip_init_task` | `0x2203118` | 每个新任务的 HKIP 初始化 |
| `cfi_harden_init` | `0x220a850` | Huawei 自己的 CFI 加固预载（走 prmem → pmalloc） |
| `selinux_protection_init` | `0x3334954` | 策略保护池的分配 |

交叉验证一处：`hkip_check_uid_root` 的前六条指令是

```
stp  x29, x30, [sp, #-0x10]!
mov  x29, sp
mrs  x8, sp_el0
ldr  w9, [x8, #0x640]        ← TASK_HKIP_XID_OFF
cbz  w9, #0xffffffc012203050 ← pid == 0 直接放行
ubfx x10, x9, #0xf, #0x11
```

`0x640` 这个偏移在 `payload/src/targets/nop_nop_an01p/target.h` 里是 `TASK_HKIP_XID_OFF`，
`cbz` 这条就是"pid==0 短路"的指令级证据——两处独立得到同一个数，才算把它钉住。

## 怎么用 tooling

```bash
pip install capstone
python tooling/kimage.py --elf vmlinux.elf sym hkip_check_uid_root
python tooling/kimage.py --elf vmlinux.elf at  0xffffffc012202fd0
python tooling/kimage.py --elf vmlinux.elf dis hkip_check_uid_root
python tooling/kimage.py --elf vmlinux.elf u32 0xffffffc012202fd0      # → 0xa9bf7bfd
```

`--elf` 省略时取 `$KIMAGE`，再退到当前目录 `vmlinux.elf`。任何同构建的 vmlinux ELF 都能用。

## 完整报告

`reports/temp-root-report.md` 是整条线的主报告：从"这机器上普通 root 为什么不可能"一路写到"哪些边界是实测撞出来的"。
`reports/pitfalls.md` 收的是上游文档里会把人带偏的说法（每条都给了反例）。
`reports/verify-vs-upstream.md` 是拿本机反汇编与上游 GhostLock 分支逐项对表的结果——差异都在这里，别去上游找。
