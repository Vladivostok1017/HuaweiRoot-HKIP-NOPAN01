# CREDITS / 依赖与参考

本仓库的研究建立在这些上游工作之上。源码本体不随仓库分发（见 `.gitignore`），此处仅列出关系与出处。

## 直接使用的项目

| 项目 | 用途 |
|---|---|
| **GhostLock / CVE-2026-43499**（HWWLZ 分支，`Eknight-Eutopia-GhostLock-Huawei-HWWLZ-0047e27`） | exploit 骨架：pselect waiter、CFI fops 劫持、pipe physrw、`hvc_inject` 与 HKIP HVC 的调用形态 |
| **NanoTurtle `cve-2026-98260`** 文档树 | 偏移提取、`/proc/kallsyms` → 符号表、BTF 对照的方法论 |
| **toybox / mksh** | 目标端的 `sh`、`dd`、`ps`、netstat 等 |

## 研究参考（思路，不含代码）

| 来源 | 我们用到的部分 |
|---|---|
| **TASZK Labs — Don't Believe The Hype(rvisor)** 及 HHEE/HKIP 系列 | HVC 无调用者校验、`HKIP_HVC_RO_MOD_UNREGISTER`、`selinux_pool` 是 `ro_recl` 而 `selinux_prot_pool` 是 `ro_no_recl`、位图需经 HVC 更新 |
| **Impalabs — Huawei Security Hypervisor** | HHEE 对 guest 页表写入的 stage-2 干预（解释 `set_memory_rw` 为何可能无效） |
| **KernelSU / SukiSU / ReSukiSU** | 管理器形态与 App 侧交互的参考；本机 `MODULE_SIG_FORCE=y` + 无 kprobes，其 LKM 路线不可移植 |
| **Shizuku** | "手机上自举 adb 权限"的思路（本机无线调试 UI 隐藏，最终走 `adb tcpip`） |
| **Termux** | 终端页的交互与配色参考（深色、等宽、单提示行、↑/↓ 历史） |
| **AOSP SELinux / sepolicy 文档** | `avtab`、`avc`、`sidtab` 结构与本机反汇编的对照 |

## 数据来源

- 内核符号与反汇编：设备自带 `vmlinux` 提取物 + `llvm-objdump`（符号表 213k 条，不随仓库分发）。
- 策略原文：设备 `/sys/fs/selinux/policy` 反编译出的 CIL（不随仓库分发）。
- 全部"实测"结论均来自本机真机运行日志，`probe/ab_summary.csv` 记录了逐次尝试的结果分类。

## 许可

本仓库以 **GNU GPL v3.0** 发布，全文见 [`LICENSE`](LICENSE)。可以自由使用、修改、再分发；派生作品需同样以 GPL 开放源码。

`payload/src/` 的 exploit 骨架来自 GhostLock 的 HWWLZ 分支，上游仓库没有标注许可；本仓库收录的是在 NOP-AN01P 上适配后的版本，出处见上表。
`docs/` 的分析结论可自由引用，注明出处即可。
