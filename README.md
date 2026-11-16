# HuaweiRoot-HKIP-NOPAN01

一台锁着 bootloader 的华为 Mate 40 RS，跑 HarmonyOS 4.2 / kernel 5.10.43。
这个项目让它能执行 `uid=0` 的命令，并且把这件事做成一个你在手机上能直接用的东西。

不是刷机包，不是 Magisk 模块，不需要解锁、不需要动 `/system`。
一次开机打一次洞，之后拔掉数据线，在手机上开终端敲命令；重启后回到原样，再打一次。

用的是 CVE-2026-43499（GhostLock，futex PI 链表上的 UAF）。

---

## 项目里有三样东西

**门（payload）** — 一个被注入到内核上下文里运行的进程，叫 `l5`。
它不常驻内核，也不改任何内核代码：手上握着一个物理内存任意读写的能力，靠它去改"我是谁"。
它只做一件事——把某个进程的 cred 改写成 `uid=0`，然后把控制权交出去。

**管理器（App）** — `com.l5.root`。它站在门和用户之间：
门只认一个邮箱目录（`/sdcard/Android/data/com.l5.root/files/l5/`），App 往里写命令、读出结果。
打开 App 看到的是 KSU 风格的主页（状态、调用者、模块位），底部切到终端就是一台黑底等宽的 shell。

**文档集（docs）** — 写这套东西时撞出来的东西：EL2 那层 HKIP 在哪几个指令上做检查、SELinux 策略体在内存里长什么样、分区和镜像的元数据怎么读。
每条结论都能指到具体地址或实测日志，不是推测。

---

## 用起来是什么样

装上管理器、打一次洞，之后有三种用法：

**在手机上敲命令。** 打开 App → 底部「终端」→ 输入 → 回车。
输出的第一行通常是：

```
uid=0(root) gid=2000(shell) groups=2000(shell) context=u:r:shell:s0
```

**保持一个会话。** 终端右上角可以在「单次」和「会话」之间切。
会话模式下 `cd`、环境变量、后台任务都留着，跟在电脑上开个 shell 一样。

**让别的 App 用。** 管理器对外是一个 ContentProvider：

```java
Bundle r = getContentResolver().call(
    Uri.parse("content://com.l5.root.gateway"), "exec", "id", null);
String out = r.getString("out");
```

`app_demo/` 里有一个 12 KB 的演示 App（`com.l5.demo`），干的就是这件事。
管理器会把调用者记在主页的「超级用户」里——谁是哪个包、什么时候来的、要了什么。

---

## 怎么开始

```powershell
# 1) 编译门和管理器
.\payload\build.ps1
.\app\build.ps1

# 2) 打洞。每次尝试都会重启设备，命中率大约 1/6，所以给 6 次机会
.\tools\probe.ps1 -settle fixed -fixedSeconds 60 -max 6 -tag run1 `
  -lean -serve -noRetry -reqPrefix "srvroot" -launchPkg com.l5.root -console

# 3) 脚本打出 "e2e status written" 就是落地了。拔线，开 App
```

落地之后屏幕上会留下几行 `[*]` 日志，`probe/ab_summary.csv` 记着每次尝试的结果。

---

## 它是怎么成立的

一句话：华为在 EL2 上加了一层自己的完整性保护（HKIP/HHEE），普通提权手法到它面前全部作废，所以要绕开的是"它允许谁是 root"这个判定，而不是"root 该有什么权限"。

链条有四段：

1. **进内核** — `select`/`pselect` 的等待队列上有一个可用的 UAF，用它把 `ashmem` 的 `file_operations` 换成自己的，拿到一个可控的 CFI 调用点。
2. **拿物理内存读写** — 从 `pipe_buffer` 的页指针走出来，绕开 `mm` 直接按物理地址读写字。
3. **问 HKIP 要许可** — EL2 维护一个 uid-0 位图。通过 hypervisor call 把目标 tid 的位打上（一次调用写 8 个 tid），这个进程之后就"被承认"是 root。
4. **改 cred** — 在物理内存里把 `cred` 结构里的 uid/gid/capabilities 写掉，然后正常返回用户态。

门进程自己留在 `uid=2000`（这是它还能读写 `/sdcard` 邮箱的原因），被它放出去的子进程才是 `uid=0`。
所以门可以反复用，一次开机里想开多少个 root 进程就开多少个——只有第一次需要打洞。

为什么别的路都不通，`docs/02` 里逐条记了：`MODULE_SIG_FORCE=y` 加没有 kprobes，KernelSU 那套内核模块加载不了；`/system` 是 erofs + verity；SELinux 策略体和 avtab 都在 EL2 只读的内存池里，改不动。

---

## 目录

```
payload/      门：注入用的 .so、root 服务进程、本机偏移表（C，NDK clang 直接编）
app/          管理器 App（Java，无 AndroidX，手工 aapt2/javac/d8/apksigner 构建）
app_demo/     演示 App：让第三方通过 Binder 借 root
tools/        落地脚本 probe.ps1
docs/         研究文档
research/     系统本身的研究材料：内核配置、QEMU 补丁表、gate 反汇编、策略体哈希、三轮报告
probe/        落地统计（ab_summary.csv）
```

目录入口：门的源码与编译说明见 [`payload/README.md`](payload/README.md)，
管理器的两个页面与协议见 [`app/README.md`](app/README.md)，
系统研究与工具见 [`research/README.md`](research/README.md)。

| 文档 | 讲什么 |
|---|---|
| [`docs/01-hkip.md`](docs/01-hkip.md) | HKIP/HHEE：`copy_process` 和 `prepare_creds` 上的检查点、`pid==0` 短路、uid 位图与 `ROWM_WRITE_8` 的语义 |
| [`docs/02-exploit-chain.md`](docs/02-exploit-chain.md) | 四段链条、每段的判据、落地率、试过但走不通的路 |
| [`docs/03-selinux.md`](docs/03-selinux.md) | 策略体与 avtab 的内存布局、桶哈希（7/7 复现）、prmem 池、为什么 AVC 投毒没用 |
| [`docs/04-system-image.md`](docs/04-system-image.md) | 分区枚举、块设备许可、boot/AVB 与压缩镜像的字段表 |
| [`docs/05-manager-protocol.md`](docs/05-manager-protocol.md) | 邮箱协议、全部动词、Binder 网关、会话模式 |
| [`docs/06-capability-matrix.md`](docs/06-capability-matrix.md) | 能力对象：门 / 终端 / 网关 / 文档集 |

---

## 研究对象不止是 root

这套东西真正的产出是两份"地图"。

**一是保护层的地图。** HKIP/HHEE 闭源、公开分析极少，而且和上游 Linux、AOSP SELinux、Magisk/KernelSU 的前提都不一样——
它不认识 `cap_capable` 的返回值，只认自己在 EL2 里维护的位图；uid 0 的任务要在 `copy_process` 和 `prepare_creds` 各过一道，没过就让设备复位。
哪几条指令上做检查、哪个条件能短路、位图的粒度是多少、hypervisor call 的编号和参数格式，`docs/01` 全部落到指令级。

**二是系统本身的地图。** 分区表、boot 与 AVB 的字段、erofs + verity 的布局、SELinux 策略体的结构和哈希算法（能自己算出某个 `(src, tgt, cls)` 落在哪个桶），
这些读出来的东西和 root 无关——它们回答的是"这台机器是怎么组织起来的"。`docs/03`、`docs/04` 记的就是这些。

原始材料放在 [`research/`](research/README.md)：设备的内核配置、把内核镜像补到 QEMU 跑起来的逐条补丁表、
四个 HKIP gate 的反汇编、avtab 哈希的拟合脚本、以及三轮完整报告。符号、偏移、反汇编都由
[`research/tooling/kimage.py`](research/tooling/kimage.py) 从 vmlinux 现取，可以自己复核。

---

## 已知边界

门拿到的是 `uid=0` + 全 capabilities，跑在 `u:r:shell:s0` 这个域里。
所以 DAC 层面畅通（能读写 root 属主的文件、能进 `/data/system`），但 SELinux 判定照旧——`mount` 在能力检查之前就被拒，`/dev/block` 读不出分区内容，别的 App 的私有数据还是看不到。
重启后一切回到原样。

---

## 许可

GNU General Public License v3.0，全文见 [`LICENSE`](LICENSE)。
上游与参考项目见 [`CREDITS.md`](CREDITS.md)。
