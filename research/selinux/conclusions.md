# Mate 40 RS（NOP-AN01P）临时 root — 结论存档

设备：`4EU0222111007420` / NOP-AN01P / NOP_AN00 / Kirin 9000 / HarmonyOS 4.2 / kernel 5.10.43 / 39-bit VA
漏洞：CVE-2026-43499（GhostLock，`kernel/locking/rtmutex.c` `remove_waiter()` 用 `current` 清 `pi_blocked_on` → 内核栈悬空 UAF）
日期：本会话

---

## 一、结论摘要

1. **五步链已全程跑通，并实测拿到 uid=0**：
   `phys step pipe probe found=1` → `probed read/write/read64 ok=1` → `root cred patched uid=0/0` → `su daemon ready pid=… socket=@cve43499_su uid=0 euid=0`
2. **但 root 窗口≈0**：拿到 uid=0 后设备必在数秒内 panic（见 §六：B 类崩溃），因此"可用 root"尚未达成。
3. **能跑通的关键是"尽量复用上游代码 + 只保留有实测依据的设备适配"**。最终净改动 7 个文件，其中 `pipe.c`、`preload.c`、`common.h`、`layout.h`、`offset.h` 与华为上游 **逐字节相同**。
4. 全程被实测否定的自造改动共 6 项（§五），其中 4 项已回退。

---

## 二、目录与基线（不再混淆）

| 路径 | 角色 |
|---|---|
| `ref/hwwlz_0047e27/GhostLock-Huawei-HWWLZ-0047e27/` | **干净基线**：华为上游精确提交 0047e27，只读 |
| `ref/hwwlz_pristine/…-main/` | 华为上游 main（已漂移） |
| `ref/s22u_full/IonStack-S22U-main/` | S22U 完整源码（5.10，MEMORY.md 记录到成功） |
| `ref/src_oneplus/JoinChang-ghostlock-oneplus-9b2a7ba/` | OnePlus（`src/core/umh_root.c` 是 ⑤ 的关键参考） |
| `ref/src_hwwlz/Eknight-…-0047e27/` | **我们的工作树**（= 基线 + 我们的改动 + `nop_nop_an01p/`） |
| `our_patches/` | 我们对基线的全部改动（unified diff，按文件） |

---

## 三、相对华为 0047e27 的净改动

```
fops.c   +586   UAF 时序适配(含 consumer delay 50000) + 大量诊断日志 + ④ 后还原 fops（B 配置）
main.c    +17   pselect 关键窗口内禁止日志
root.c    +22   ⑤ 读写改为 pipe 优先 + data_addr() 转换（移植 OnePlus umh_root.c）
slide.c   +14/−4 tracefs 按函数名匹配
util.c    +18   try_to_wake_up+0x9d0 自指针
target.h +305   自建逐设备偏移
entry.c   +14   自建、Makefile 不引用（待删）
```

`pipe.c` / `preload.c` / `root.c` 以外的公共头 / `layout.h` / `offset.h` / `common.h` **与上游一致**。

### 每处改动的依据

| 改动 | 依据 |
|---|---|
| `util.c` `put64(p, FAKE_TASK_OFF+0x9d0, fake_task)` | 静态：`try_to_wake_up` 在 `+0x60 add x8,x19,#0x9d0` / `+0x64 ldar` / `+0x68 ldr x8,[x8,#8]`（该解引用在 `+0x4c` 状态测试**通过之后**执行）；动态：ramoops `pc: try_to_wake_up+0x68, addr 0x8, x19=fake_task` |
| `slide.c` 改成按 `funname=="worker_thread"` 匹配 | 上游硬比较 `off==0x590 && size==0x960` 是 nova6 量测值，本机不符 ⇒ 实测 8/8 全挂 `slide tracefs worker caller not found` |
| `main.c` 窗口内不打日志 | S22U MEMORY.md §4f 硬不变量；实测带这两条 `pr_info` 时 3/3 死在 `one-punch leftover` |
| `root.c` pipe 优先 + `data_addr()` | OnePlus `src/core/umh_root.c:76-89`（"pipe physrw primary, configfs fallback"），其对 `selinux_state` 正是先 `data_addr()` 再交给 pipe；实测由此得到 `root cred patched uid=0/0` |
| `fops.c` ④ 后还原 `ashmem_misc.fops` | 为了消除 B 类崩溃；**属 B 配置，尚未验证** |

---

## 四、两种配置的验证状态

| 配置 | 内容 | 状态 |
|---|---|---|
| **A** | 上游 `root.c` 或 pipe 优先 `root.c`，**不**提前还原 fops | ✅ 两次不同构建都实测拿到 `uid=0`：`5CA8CFED…`（上游 root.c）、`5E80B5A8…`（pipe 优先 root.c） |
| **B** | ④ 之后立即还原 `ashmem_misc.fops` | ❓ 从未走到 ⑤（多次运行都停在 pselect 或 pipe 准备阶段） |

构建哈希（`build/nop_nop_an01p/bin/preload.so`）：
- A（pipe 优先）：`5E80B5A8F64D9F6C8AA0BE44115B5262B4985B2C8EEA5E0A83F873EC8E0B3D84`
- B（提前还原）：`A4961882372D449F1C8754F3F1F2186158B7331702FA5CF401A6096861297BB8`

---

## 五、被实测否定并回退的做法（教训）

1. **`VMEMMAP_START` 改为 `0xfffffffe00000000`** —— 错。S22U MEMORY.md §4c 说明该常量含 `(memstart>>12)*0x40` 的抵消约定，`pipe.c` 的 va→page 故意不漏 memstart；改动破坏抵消，改完立刻崩。**已回退为 `0xfffffffeffe00000`**。
2. **`configfs_write_once` 用 12-bit 掩码** —— 错。上游用 **24-bit**（`pos = target & 0xffffff`），页/16MB 对齐使低 3 字节恒为 0，天然"掩码安全"；我们改成 12-bit 后被 `strscpy` 掩码抹掉中间字节，写飞进 `.rodata`。**已回退为上游**。
3. **自造"精确建模掩码 + `*ppos` 补差额"** —— 重复发明，上游 24-bit 方案已解决。
4. **`pipe.c` 加进程内扫描重试 / payload check / `flush_mm_cpu_partial`** —— 上游 `fops.c` 本来就有 `PIPE_MAX_ATTEMPTS(12)` 循环包 `install_child_root`。**已整体撤回，`pipe.c` 与上游逐字节相同**。
5. **"跳过自检"的早退分支** —— 上游没有。撤掉后整条 CFI 校验链全部通过（`ret=35` / `llseek repair got=NOOP_LLSEEK` / `cfi read ret=35` / 还原 / 表刷新）。
6. **pre-check 后立即还原 fops** —— 错。后续 `leak_kernel_base()` 要靠 `ashmem_misc.fops` 里仍是 fake 值推 slide/别名，还原过早链条断在验证写之后。
7. **`root.c` 一律走 pipe（不做 `data_addr()`）** —— 错。`pipe_phys_*` 的 `is_direct_ptr()` 会拒掉 kimage 地址 ⇒ ⑤ `uid=2000->-1`。

---

## 六、两类崩溃（都已取到硬件级证据）

| 类型 | 现象 | 证据 |
|---|---|---|
| **A** | `try_to_wake_up+0x68`，`[fake_task+0x9d0]` 读到 0 | ramoops `Code: 11000508 b904bb28 91274268 f8bfc108 (f9400508)`（即 `add x8,x19,#0x9d0; ldar; ldr x8,[x8,#8]`）。属 payload 页被复用的概率性失败 |
| **B** | `configfs_read_file+0x1ac`，源地址 `0x0063615064656c6c` = ASCII `"lledPac"` | 来自 `/dev/ashmem/Instance/Stalled Package` 的名字字符串。机制：劫持期间 `misc_open()` 把 fake 表发给**任何**进程，其 asma+0x10（page）落在自己名字里 → `read()` 从"字符串地址"读 |

B 是"拿到 uid=0 后立刻失效"的直接原因，也是配置 B 想消除的东西。

### 静态分析已到头

payload 布局经静态验算无误：写在 `skb_buf + SKB_FRAG_BIAS(0xE80)`，`fake_task+0x9d0` 对应 buffer 偏移 `0xE80+0x3200+0x9d0 = 0x4A50 < SKB_SEND_SIZE(0x8E80)`，页内偏移 `0x3BD0 < 0x8000`。剩下的只是"哪一页/哪一刻"的运行时问题。

---

## 七、量化统计（今日全部日志）

| 指标 | 数值 |
|---|---|
| 总运行次数 | 41 |
| UAF 命中（`cfi pre-check rb=8`） | 13 次 ≈ **32%** |
| 命中后还通过 pipe 准备 | 2 次 |
| 两者同时成立 | 2 / 41 ≈ **5%** |
| 单次运行耗时 | 19–23 秒 |
| panic 后设备恢复 | 38–55 秒 |

⇒ 验证配置 B 平均需要约 20 次运行（20–25 分钟设备时间）。

---

## 八、工具/环境坑（都已踩过）

1. **adb server 会卡死**：`adb devices` 空但手机其实连着。修：`adb kill-server; adb start-server`。
2. **`adb shell` 会永不返回**：exploit fork 的子进程（parked waiter、`sleep(60)` 的 pipe 子进程、su daemon）继承 pty 的 stdin/stdout，即使 `timeout` 杀掉直接子进程，孙进程仍持有通道。对策：设备端 `timeout N` + `< /dev/null`，或把输出重定向到文件。
3. **`/data/local/tmp` 在 panic 重启后被清空**：日志不要写在那里指望事后读；每次重启后必须重新 `push` + `chmod 755`（否则 exit 126）。
4. **不要用 `| tail`/`grep` 过滤设备端输出**：panic 时管道未到 EOF，输出会被吞。
5. 静态环境：本机无 `make`，用 `build_nop.ps1`（NDK r27c clang，`--target=aarch64-linux-android35`、`-DTARGET_CONFIG_H=<targets/nop_nop_an01p/target.h>`、`su_daemon.c` 先编 PIE 再由 `su_blob.S` 内嵌）。
6. Python 可用但 **stdio 重定向/管道会被沙箱拒绝**；`llvm-objdump`、WSL、`git` 在本会话早期均被拒（后期 `git` 可用）。

---

## 九、未完成 / 未验证

1. **配置 B（提前还原 fops）从未走到 ⑤** —— 需要更多命中来判定；这是让 root 可用的关键一步。
2. **pipe 准备命中率**（12 次 UAF 命中仅 2 次通过）—— S22U §4d 用 `/proc/buddyinfo` 驱动 absorb；本机该文件被 SELinux 拒（`mm order3 absorb: buddyinfo unreadable, filling to cap`），如何取得等价信息未定。
3. **SELinux / HKIP**：`CONFIG_SECURITY_SELINUX_DEVELOP` 未开（`enforcing` 字段不存在）。dawnslab（华为 README 指向的文章，已取回）给的路径是改 `policydb->allow_unknown=1` 或破坏 `map->mapping` 使 `unmap_class()` 返回 0；HKIP 保护代码段/只读数据/内核页表，但**不保护其余结构体与应用页表**。
4. 母本 README 的既有结论：hkip 拦 su 常驻、SELinux 关不掉。

---

## 十、复现步骤

```powershell
# 1) 构建（等价于 Makefile 的 NDK recipe，含 su_daemon PIE 内嵌步骤）
& '<workspace>\build_nop.ps1'
#    -> build/nop_nop_an01p/bin/preload.so

# 2) 推送（每次设备重启后都要重做，含 chmod）
adb -s 4EU0222111007420 push build\nop_nop_an01p\bin\preload.so /data/local/tmp/glp.so
adb -s 4EU0222111007420 shell 'chmod 755 /data/local/tmp/glp.so'

# 3) 运行（这是唯一验证有效的写法；不要加 tail/grep）
adb -s 4EU0222111007420 shell 'cd /data/local/tmp; LD_PRELOAD=/data/local/tmp/glp.so /system/bin/sh -c "true" 2>&1'
```

成功标志（按出现顺序）：

```
[+] slide-kaslr-ok source=tracefs ...
[*] cfi pre-check rb=8 fops=... want=...            ← UAF 命中
[*] phys step pipe probe found=1 ... scan=1/1/1
[*] phys step probed read done ok=1 / probed write done ok=1 / read64 done ok=1
[*] root cred patched uid=0/0 ...
su daemon ready pid=... socket=@cve43499_su uid=0 euid=0
```

---

## 十一、关键文件索引

| 文件 | 内容 |
|---|---|
| `RESULT_temp_root.md` | 首次跑通时的记录（本文件的前身） |
| `step4_progress.md` | ④ 的推进过程：configfs 写原语、VMEMMAP、pipe 阶段 |
| `upstream_pitfalls.md` | 四个开源项目的踩坑记录与对应关系（S22U §4b/4d/4e/4f、VMEMMAP 抵消规则） |
| `verify_vs_hwwlz.md` | 26 项偏移/常量核验 + 用上游 `extract_target.py` 实跑的交叉验证 |
| `our_patches/*.patch` | 相对华为 0047e27 的全部改动 |
| `build_nop.ps1` | 构建脚本 |
| `run_*.log`、`batch_*.log`、`attempt_*.log` | 运行日志（含命中与各阶段失败实例） |

---

## 十二、可用 root 已达成（本会话最新结论，已稳定复测）

### 结果

```
$ /data/local/tmp/su -c id
uid=0(root) gid=2000(shell) groups=2000(shell),1004(input),... context=u:r:shell:s0
$ grep Cap /proc/self/status   (在 root 上下文内)
CapPrm: 000001ffffffffff        CapEff: 000001ffffffffff
getenforce → Enforcing
```

设备**不再 panic**（uptime 2 min +，间隔 60 s 两次复测均返回 uid=0）。此前"root 窗口≈0"由此消除。

### 使能条件（两条，缺一不可）

**1. exploit 必须脱离 pty 启动（这是根因，此前一直缺失）**

门禁服务端 `hkip_service_windows()`（`root.c:421-457`）在**父进程**里是 `for(;;)`，成功后永不返回
—— 这解释了为什么成功轮永远没有 `summary` 行、也没有 `main.c` 收尾。若按老写法用普通
`adb shell` 跑，adb 断开时 SIGHUP 会打死整个前台进程组 → 服务端死 → 之后每次 `su -c`：

- 客户端发请求 → daemon 的 `exec_command_client()` → `hkip_prepare_exec()` → `hkip_gate_request()`
  （`hkip_gate.h:43-57`）等 `8000 × 1 ms` 无人应答 → 返回 0 → `_exit(125)`；
- 外部表现：**~8.9 s 后返回、零输出、零副作用、客户端 rc=0**（实测与静态完全一致）。

正确启动方式（每次重启后需先 push + chmod）：

```sh
adb shell 'cd /data/local/tmp; setsid env LD_PRELOAD=/data/local/tmp/glp.so \
  /system/bin/sh -c true >/data/local/tmp/gl.log 2>&1 </dev/null &'
```

**2. 配置 B（④ 后还原 `ashmem_misc.fops`）+ ⑤ pipe 优先**

即存档 §四 的 B 配置 + `root.c` 的 pipe-primary/`data_addr()` 适配，构建哈希
`A4961882372D449F1C8754F3F1F2186158B7331702FA5CF401A6096861297BB8`。
`root.c` 的 `root_write_data()` 走 pipe 原语，所以还原 fops 后门禁服务仍能工作，
同时不再留 B 类地雷（`misc_open()` 把 fake 表发给别的进程）。

### 被否定的做法

**照抄 S22U `spawn_allocation_keeper()`（`src/main.c:142-176`，纯 `nanosleep`）是无效的**：
它挂在 `main.c` 收尾，而成功路径根本走不到收尾（父进程卡在门禁服务循环），属不可达死代码。
我们的 `hkip_service_windows()` 本身就等价且更强——其注释即
"Stay up so later /data/local/tmp/su clients can request windows"，且必须**持续**服务新 pid。
已完整回退，构建哈希回到 `A4961882…`。

### 当前限制（未变）

SELinux 仍 `Enforcing`、domain 仍 `u:r:shell:s0`（HKIP 保护 SELinux 且 `CONFIG_SECURITY_SELINUX_DEVELOP` 未开），
所以 uid=0 + 全 caps 仍被 SELinux 拒绝访问 `/data/data`、`/proc/sys/kernel/kptr_restrict` 等。
下一步仍是 dawnslab 路线（`policydb->allow_unknown=1` 或破坏 `map->mapping` 使 `unmap_class()` 返回 0）。

---

## 十三、SELinux / AVC 专门存档

完整结论见 `SELINUX_AVC_findings.md`，要点：

- 本机 `CONFIG_HKIP_SELINUX_PROT=y` + `HKIP_PRMEM=y` ⇒ **policy 池 EL2 只读**，写 `policy+0x254/0x260` 实测 panic。
- 本内核 `security_compute_av` 的真实放行判据是 `*(selinux_state+8)` 的首字节 bit0（实测 `0xfffffffe87ff0ff8 -> 01`），写它同样 panic。
- `selinux_state.initialized` 本来就是 0，不是本内核的判据。
- **AVC 结构已完全解出**（5.10：`slots` 在 `avc+0x8`、槽存 `&node->list`、`node=entry-0x28`、`allowed@node+0x1c`），槽表可一次 4KB 读出，节点字段可读；写入受 `HARDENED_USERCOPY`/劫持窗口/pipe 依赖 configfs 三重限制，尚未完成。
- 两条机制性约束：① 劫持窗口内任何进程 `open("/dev/ashmem")` 会 panic（B 类）；② **pipe 原语依赖 configfs** 伪造 pipe_buffer，还原 fops 后即失效（实测 `copy_page_to_iter` oops）。
- 寻址：本机只能用 `text_addr()` + configfs 读镜像数据；`data_addr()` 的物理别名假设不成立。
- 与文献差异原因：Klecko/TASZK 的"华为有效"来自 Mate 20 Pro / P40 等较老内核；TASZK 在 Mate 40 上的成功依赖内核代码执行调 HVC，本镜像缺其 gadget。
- 唯一有本机型先例且未实测的路径：**只写不读的 AVC 投毒**（TASZK 原话），步骤见 `SELINUX_AVC_findings.md` §七。
