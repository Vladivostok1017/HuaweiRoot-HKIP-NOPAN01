# CVE-2026-43499 与 SELinux 宽容在华为 Mate 40 RS 上的解决方案与限制

目标机型 HUAWEI Mate 40 RS（NOP-AN01P / NOP-AN00），bootloader 锁定，未解锁、未改系统分区。
本文档描述在这台机器上取得 `uid=0` 执行能力的方案、落地方式，以及为什么 SELinux 侧的"宽容"做不到。

一次开机执行一次漏洞利用，之后可脱离电脑使用；重启后失效，需重新执行。

---

## 1. 设备与环境

| 项 | 值 |
|---|---|
| 机型 | HUAWEI Mate 40 RS（NOP-AN01P / NOP-AN00） |
| 系统 | HarmonyOS 4.2（Android 12） |
| 内核 | 5.10.43，aarch64 |
| bootloader | 锁定 |
| `/system` | erofs + verity |
| SELinux | enforcing；`CONFIG_SECURITY_SELINUX_DEVELOP` 未开启 |
| 内核模块 | `MODULE_SIG_FORCE=y`，`# CONFIG_KPROBES is not set` |
| 漏洞 | CVE-2026-43499（GhostLock，futex PI 等待链表上的 UAF） |

---

## 2. 解决方案

漏洞利用分四步，前两步是取得内核读写原语，后两步是把自己的身份改成 `uid=0` 并让系统承认这个身份。

| 步骤 | 目标 | 手段 |
|---|---|---|
| 1 | 在内核中取得可控调用点 | `select`/`pselect` 等待队列上的 UAF → 替换 `ashmem` 的 `file_operations`（CFI 劫持） |
| 2 | 任意物理内存读写 | 从 `pipe_buffer` 的页指针走出，绕开 `mm` 按物理地址读写 |
| 3 | 通过 EL2 的 uid-0 校验 | hypervisor call（`ROWM_WRITE_8`，`0xC6001054`）写 EL2 维护的 uid-0 位图；一次落地 1 字节 = 8 个连续 tid |
| 4 | 改写凭据 | 在物理内存中改写 `cred` 的 uid / gid / capabilities，返回用户态 |

第 3 步是本机与上游 Linux 的关键差别：华为在 EL2 上有一层 HKIP/HHEE，uid 0 的任务要在
`copy_process` 与 `prepare_creds` 各过一道校验，判定依据是 EL2 里的位图，而不是内核中 `cap_capable` 的返回值。
位图无法由 EL1 直接写入，只能通过内核自身的 hypervisor call 更新。检查点偏移与反汇编见 `docs/01-hkip.md` 与 `research/hkip/`。

扫描完成后，承载服务循环的进程（构建产物 `payload/build/.../preload.so`，注入后运行在管理器进程内，
早期笔记中称其为"门"）**自身保持 `uid=2000`**，从而继续读写 `/sdcard` 上的通信目录；
每条请求 fork 一个子进程、只改写该子进程的 cred、回读 EL2 位确认后再放行。
因此同一 boot 内可反复执行（实测连续 5 次均为 `uid=0(root)`），无需二次利用漏洞。

---

## 3. SELinux 宽容的可行性结论

目标是关闭 SELinux 强制模式或改写策略，使 `mount`、块设备读取、跨域访问可用。三条路径均已实测或静态确认为不可达：

| 路径 | 结论 | 依据 |
|---|---|---|
| 写 `selinux_state.enforcing = 0` | 可写但无效 | 编译时未开 `CONFIG_SECURITY_SELINUX_DEVELOP`，判定为常量；内核中 `get_selinux_enforcing` 被编译成 `mov w0, #1` |
| 改写策略体 / avtab | 不可达 | 策略体与 avtab 位于 EL2 只读内存池（`selinux_pool` / `selinux_prot_pool`）；`HKIP_HVC_RO_MOD_UNREGISTER` 只接受 EL2 已注册的精确 `(va, size)`，推测范围会导致设备复位（实测两次） |
| AVC 缓存投毒 | 无效 | 583 次投毒后判定结果仍为 `-13` |

因此实际形态是：**在 `u:r:shell:s0` 域内以 `uid=0` + 全 capabilities 运行**。
DAC 层面畅通（可读写 root 属主文件、可进入 `/data/system`），SELinux 判定照旧。
这条边界的完整清单见 `docs/06-capability-matrix.md`。

---

## 4. 项目路径

```
payload/            内核侧载荷：注入镜像、root 服务进程、本机偏移表（C，NDK clang 构建）
  src/targets/nop_nop_an01p/target.h   本机全部内核偏移
  build.ps1                           产出 preload.so 与 su_daemon
app/                管理器 App：主页 + 终端、文件邮箱客户端、Shizuku binder 客户端、对外 Binder 提供方
app_demo/           第三方调用示例（com.l5.demo）
tools/probe.ps1     漏洞利用执行脚本（重启 → 等待稳定 → 注入 → 判定落地）
docs/               方案文档：HKIP、漏洞链、SELinux、系统镜像、协议、能力矩阵
research/           系统本身的研究材料与工具
  system/           设备内核配置全文
  qemu/             将内核镜像静态补丁至可在 QEMU 运行到用户态的补丁表
  hkip/             HKIP 检查点、上下文切换、策略加载函数反汇编
  selinux/          策略体布局、avtab 桶哈希拟合、AVC 结论
  init-domain/      init 域能力边界与 mount 可行性
  tooling/          kimage.py：符号 / 地址 / 反汇编 / 读内核数据
  reports/          三轮完整报告
probe/              执行记录（ab_summary.csv）
NEXT.md             交接：已验证项、待验证项、改动成本
```

载荷源码说明见 `payload/README.md`，管理器说明见 `app/README.md`，研究材料索引见 `research/README.md`。

---

## 5. 构建与执行

```powershell
# 1) 构建载荷与管理器
.\payload\build.ps1
.\app\build.ps1

# 2) 执行漏洞利用：每次尝试会重启设备，命中率约 1/6，故给 6 次机会
.\tools\probe.ps1 -settle fixed -fixedSeconds 60 -max 6 -tag run1 `
  -lean -serve -noRetry -reqPrefix "srvroot" -launchPkg com.l5.root -console

# 3) 输出 "e2e status written" 即落地成功；之后可断开数据线，在 App 内操作
```

落地后验证：

```
$ id
uid=0(root) gid=2000(shell) groups=2000(shell) context=u:r:shell:s0
```

载荷镜像存在尺寸上限 161,144 字节（当前构建 158,808 字节）。

---

## 6. 能力与限制

| 可用 | 不可用 |
|---|---|
| 以 `uid=0` + 全 capabilities 执行任意 shell 命令，同一 boot 内不限次数 | 关闭 SELinux 强制模式或改写策略（见第 3 节） |
| 读写 root 属主文件、进入 `/data/system` 等 DAC 受限路径 | `mount` / overlay / bind 挂载（在能力检查之前即被域策略拒绝） |
| 会话模式保留 `cd`、环境变量、后台任务 | 读取 `/dev/block` 分区内容（shell 域对 `blk_file` 仅有 `getattr`） |
| 第三方 App 通过 `content://com.l5.root.gateway` 请求代执行 | 加载内核模块（`MODULE_SIG_FORCE=y`，无 kprobes） |
| 载荷在 `restart zygote` 中存活，提供一次可控的系统启动窗口 | 跨真实重启保持状态（无 `/data/adb`，无早期时序） |

---

## 7. 研究产出

除执行通道外，本仓库包含两部分针对这台机器本身的测量结果。

**保护层。** HKIP/HHEE 为闭源实现，行为与上游 Linux、AOSP SELinux、Magisk/KernelSU 的假设均不兼容。
本仓库给出其检查点所在的精确符号与指令、`pid==0` 短路条件、位图粒度与 hypervisor call 的参数格式，
并附上把同一内核镜像补丁至可在 QEMU 运行到用户态的逐条补丁表（每个补丁先断言原始字节）。

**系统结构。** 分区枚举、boot 与 AVB 字段布局、erofs + verity、SELinux 策略体的内存布局与 avtab 桶哈希
（可自行复算某个 `(src, tgt, cls)` 的落桶）。这些结论与取得 root 无关。
符号、偏移与反汇编均由 `research/tooling/kimage.py` 从 vmlinux 现取，可复核。

---

## 8. 文档

| 文档 | 内容 |
|---|---|
| [`docs/01-hkip.md`](docs/01-hkip.md) | HKIP/HHEE 检查点、`pid==0` 短路、uid 位图与 `ROWM_WRITE_8` 语义 |
| [`docs/02-exploit-chain.md`](docs/02-exploit-chain.md) | 漏洞链各阶段与判定条件、落地率、已排除路径 |
| [`docs/03-selinux.md`](docs/03-selinux.md) | 策略体与 avtab 内存布局、桶哈希复现、prmem 池、AVC 投毒为何无效 |
| [`docs/04-system-image.md`](docs/04-system-image.md) | 分区枚举、块设备许可、boot/AVB 与压缩镜像字段表 |
| [`docs/05-manager-protocol.md`](docs/05-manager-protocol.md) | 文件邮箱协议、全部动词、Binder 网关、Shizuku 快通道 |
| [`docs/06-capability-matrix.md`](docs/06-capability-matrix.md) | 能力对象与逐条实测边界 |
| [`research/README.md`](research/README.md) | 系统研究材料索引与关键偏移表 |
| [`research/notes/soft-reboot-hook.md`](research/notes/soft-reboot-hook.md) | 载荷在软重启中存活，及其支撑的"本次开机内生效"形态 |
| [`NEXT.md`](NEXT.md) | 交接文档：已验证项、下一阶段任务、改动成本 |

---

## 9. 参考与许可

外部来源见 [`CREDITS.md`](CREDITS.md)，排名不分先后。
自有代码以 **GNU GPL v3.0** 发布，全文见 [`LICENSE`](LICENSE)。
