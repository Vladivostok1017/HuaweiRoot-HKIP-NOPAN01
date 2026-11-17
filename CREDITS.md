# 参考与致谢

> 排名不分先后。

- **[TASZK Labs — Don't Believe The Hype(rvisor)](https://labs.taszk.io/articles/post/hypervisor1/)** —— 华为 HHEE/HKIP 逆向分析
- **[Eknight-Eutopia / GhostLock-Huawei-HWWLZ](https://github.com/Eknight-Eutopia/GhostLock-Huawei-HWWLZ)** —— `payload/` 的骨架来源
- **[zzzxxxxxxxxxx / GhostLock-GOT-W29](https://github.com/zzzxxxxxxxxxx/GhostLock-GOT-W29)** —— 同 CVE 的另一份 PoC
- **[NanoTurtle1145 / root-my-s24](https://github.com/NanoTurtle1145/root-my-s24)** —— S24 落地实践与偏移提取方法
- **[klecko — SELinux bypasses](https://klecko.github.io/posts/selinux-bypasses/)** —— SELinux 绕过手法
- **[Impalabs — Huawei Security Hypervisor](https://blog.impalabs.com/2212_huawei-security-hypervisor.html)** —— 华为 hypervisor 分析
- **[酷安社区帖](https://www.coolapk.com/feed/74446702?s=MDFkOGU2ZmEyYWE1ODJiZzZhZmIyZjk2ega1664)** —— 借域绕 SELinux/HKIP 的思路

## 其他参考

KernelSU / SukiSU / ReSukiSU（管理器形态）、Termux（终端交互）、AOSP sepolicy（`avtab` / `avc` / `sidtab` 结构）。

**Shizuku** —— 直接使用官方 SDK `dev.rikka.shizuku:{api,provider,shared}:13.1.5`：App 把 `RootExecService` 放进它的特权进程，命令从文件邮箱提到毫秒级 binder；它"在手机上自举一个高权限通道"的思路也是这台机器离线可用的前提。

## 数据来源

设备 vmlinux（213,390 条符号，用 `research/tooling/kimage.py` 取）、设备 SELinux 策略原文、真机运行记录（`probe/ab_summary.csv`）。镜像与符号表本体不进仓库。

## 许可

**GNU GPL v3.0**，全文见 [`LICENSE`](LICENSE)。`payload/src/` 的骨架来自上面清单里的 GhostLock 分支（上游未标注许可），本仓库收录的是 NOP-AN01P 上适配后的版本。
