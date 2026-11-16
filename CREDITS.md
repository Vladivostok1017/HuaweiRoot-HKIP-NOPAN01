# 参考与致谢

> 排名不分先后。

## 清单

- **[TASZK Labs — Don't Believe The Hype(rvisor)](https://labs.taszk.io/articles/post/hypervisor1/)**
  华为 EL2 保护层（HHEE / HKIP）的公开逆向分析。本仓库对 hypervisor call 形态、`selinux_pool` 与 `selinux_prot_pool` 属于哪一类只读区、
  "位图必须经 HVC 更新"这几条判断的出发点都在这里。

- **[Eknight-Eutopia / GhostLock-Huawei-HWWLZ](https://github.com/Eknight-Eutopia/GhostLock-Huawei-HWWLZ)**
  本仓库 `payload/` 的骨架来源：pselect waiter、CFI fops 劫持、`pipe_buffer` → 物理读写、`hvc_inject` 的调用形态。
  NOP-AN01P 上的偏移、HKIP 位图用法、邮箱协议与 `srvroot`/会话形态是后来加的。

- **[zzzxxxxxxxxxx / GhostLock-GOT-W29](https://github.com/zzzxxxxxxxxxx/GhostLock-GOT-W29)**
  同一 CVE（CVE-2026-43499）的另一份 PoC。对着它核过漏洞链的阶段划分与判据——链条同源，落地条件不同，
  这也是为什么本仓库把"每阶段怎么判定成功"单独写出来（`docs/02`）。

- **[NanoTurtle1145 / root-my-s24](https://github.com/NanoTurtle1145/root-my-s24)**
  CVE-2026-43499 / CVE-2026-98260 在 Galaxy S24 系列上的完整落地实践。偏移提取、把 `/proc/kallsyms` 的符号名与
  vmlinux/BTF 对齐的方法论取自这里；`research/tooling/kimage.py` 的用法就是这套流程固化下来的结果。

- **[klecko — SELinux bypasses](https://klecko.github.io/posts/selinux-bypasses/)**
  SELinux 绕过手法的综述（策略层与 AVC 层各自能做什么）。本仓库判定"AVC 投毒在这套策略上不成立"时，
  参照的就是这里对 AVC 缓存与判定路径的区分（结论与反例见 `research/selinux/avc-findings.md`）。

- **[Impalabs — Huawei Security Hypervisor](https://blog.impalabs.com/2212_huawei-security-hypervisor.html)**
  对华为 hypervisor 的系统性分析，尤其是 stage-2 对 guest 页表写入的干预。
  这一条解释了本仓库实测到的现象：EL1 写进受保护页"写成功、回读也对、判定不认"。

- **[酷安社区帖](https://www.coolapk.com/feed/74446702?s=MDFkOGU2ZmEyYWE1ODJiZzZhZmIyZjk2ega1664)**
  同机型上的社区实测与讨论。

## 除此之外的方法与形态参考

- **KernelSU / SukiSU / ReSukiSU** —— 管理器该长什么样、App 侧怎么和内核侧对话。本机 `MODULE_SIG_FORCE=y` 且没有 kprobes，
  它的 LKM 路线搬不过来，但"主页 + 终端 + 超级用户列表"这套形态是照它做的。
- **Shizuku** —— "在手机上自举一个高权限通道"的思路。本机无线调试 UI 是隐藏的，最终走 `adb tcpip`。
- **Termux** —— 终端页的交互与配色参考（深色、等宽、单提示行、上下键翻历史）。
- **AOSP SELinux / sepolicy 文档** —— `avtab`、`avc`、`sidtab` 的结构定义，用来和设备反汇编逐字段对照。

## 数据来源

- 内核符号与反汇编：设备 vmlinux（213,390 条符号），用 `research/tooling/kimage.py` 取；vmlinux 本体不进仓库。
- 策略原文：设备 `/sys/fs/selinux/policy` 反编译出的 CIL（不进仓库）。
- 所有"实测"结论都来自真机运行记录，`probe/ab_summary.csv` 是逐次尝试的分类结果。

## 许可

本仓库以 **GNU GPL v3.0** 发布，全文见 [`LICENSE`](LICENSE)。可以自由使用、修改、再分发；派生作品需同样以 GPL 开放源码。

`payload/src/` 的 exploit 骨架来自上面清单里的 GhostLock 分支，上游仓库没有标注许可；本仓库收录的是在 NOP-AN01P 上适配后的版本。
`docs/` 与 `research/` 的分析结论可自由引用，注明出处即可。
