# Init 域路线（Mate60 L5 移植）—— 实测记录 2026-11-11

承接 `ROUND_SELINUX_2026-11-11.md`（路线 ①②③④ 存档）与
`ROUND_C_TERMINATION_2026-11-10b.md`（Route C 收尾）。

目标是 **可用 root / Magisk 模块**（不是读全部 app 数据）。本文记录把它当
L5「借域」来做时的两次实测。

---

## 零、先解决的三件事

### 0.1 路线②的开放问题 #1 已有答案：cred SID 写是**生效的**

`ROUND_SELINUX` §六.1 说 `now=`（借 SID 后回读）从未观测到，因此无法区分
「写没生效」和「SELinux 仍拒」。实测（构建 `9E74831F`，159768 B）：

```
initdom sid=70 now=70 w=1/-1 | ...
```

`w` 是 `patch_cred_sid()` 的返回值，`now` 是写后回读。**写成功、回读一致。**
所以路线② 的负结果不是写原语的问题；`pipe_phys_write_data` 对 kmalloc 的
`cred->security` 是好用的（`CONFIG_HKIP_PROTECT_CRED` 未开，纯数据写）。

顺带确认 `own=2130/2130`（自身 shell SID=2130），`selinux_cred_blob_off=0`，
与 `target.h` 的 `SELINUX_CRED_BLOB_OFF 0` / `SID_OFF 4` / `CRED_SECURITY_OFF 120`
完全自洽 —— 偏移表没问题。

### 0.2 pid 1 的 SID = **70**，osid = 1

```
initdom pid1 task=ffffff803114db80 cred=ffffff81908033c0 sec=ffffff805c9bc1c0 osid=1 sid=70
```

`osid=1` 正好是 kernel SID，符合「init 由 kernel_execve 创建」这一事实，是这个
读取可信的旁证。

**不能静态推这个数**：`(sidcontext init (u object_r unlabeled ...))` 说明
sidorder 里的第 7 个「init」是 `u:object_r:unlabeled:s0`，不是 `u:r:init:s0`；
非初始 SID 是运行时查表分配的（我们自己的 shell 是 2130）。所以只能读。

**sid 70 的域名字符串已确认，而且不用漏洞**：

```
$ adb shell cat /proc/1/attr/current
u:r:init:s0
$ adb shell ls -lZ /proc/1/attr/current
-rw-rw-rw- 1 root root u:r:init:s0  0 … /proc/1/attr/current
```

即 **sid 70 = `u:r:init:s0`**，这一格不再需要消耗探针去问。

顺带一条免费情报通道：`/proc/<pid>/attr/current` 权限是 0666，**shell 域就能读
任何进程的域名字符串**。已用它枚举本机在跑的域，其中有 `u:r:vold:s0`（pid 532）
—— vold 是 Android 上真正执行 mount 的守护进程，是「借域做 Magisk」比 init 更
合理的候选。以后选域之前先看这张表，不要再凭猜。


### 0.3 文件标签真值（`ls -Z`，无需漏洞，shell 即可）

```
u:object_r:system_data_root_file:s0        /data
u:object_r:shell_data_file:s0              /data/local/tmp
u:object_r:system_data_file:s0             /data/user
u:object_r:system_data_file:s0:c512,c768   /data/user/0     <-- 类别在目录本身上
u:object_r:system_file:s0                  /system
-rw------- 1 root root u:object_r:system_file:s0  /system/build.prop
```

两条要点：

1. `/data` 是 `system_data_root_file`（不是 `system_data_file`），所以「init 能
   进 /data 却进不去 /data/user/0」并不矛盾——挡在 `/data/user/0` 自己身上。
2. **`/data/user/0` 自带 MLS 类别 `s0:c512,c768`**，这条就把路线② 的结论钉死
   了：任何 `s0` 域（shell/system/**init**）都过不了 `(dom l1 l2)`。借「域」没用，
   只有借那个 app 的 SID 才有用——与 `ROUND_SELINUX` §2.1 的静态判断一致，现在是
   实测证据了。

---

## 一、实测：借 init 域（构建 `9E74831F`）

做法：把 pid 1 的 cred 里的 `{osid,sid}` 写进自己（与 pre-exec 子进程共享）的
cred，**uid 保持 0**（`/data/adb` 是 root 所有，DAC 走属主检查，不触发被 HKIP
拦的 `CAP_DAC_OVERRIDE`），随后在进程内直接试操作，不做 execve（exec 会按策略
重算 SID，测不出东西）。

```
initdom sid=70 now=70 w=1/-1 | adb=-1/13 mk=-1/13 user0=-1/13 sysprop=-1/13 tmp=1108/0 mp=0/0 mnt=-1/13
initdom restored sid=2130 want=2130
```

| 探针 | 结果 |
|---|---|
| `open("/data/adb")` | `EACCES(13)` |
| `mkdir("/data/adb/.cve43499_probe")` | `EACCES(13)` |
| `open("/data/user/0")` | `EACCES(13)`（MLS，见 0.3） |
| `open("/system/build.prop")` | `EACCES(13)` ← **意外** |
| `open("/data/local/tmp")` | OK（fd=1108） |
| `mkdir("/data/local/tmp/.cvmp")` | OK |
| `mount("tmpfs", .../.cvmp, ...)` | `EACCES(13)`（不是 EPERM） |

`mount` 返回 **EACCES 而不是 EPERM** 曾被当作「能力检查过了」的证据，**这条推断是错的，已撤回。**

本机反汇编 `path_mount`（`0xffffffc0104c386c`）给出的真实顺序是：

```
0xffffffc0104c38f0  ldr x20,[x26,#0x18]     ; 第一个 security_hook 链
0xffffffc0104c3904  blr x20                 ;   = security_sb_mount(dev,path,type,flags,data)
0xffffffc0104c3908  cbnz w0, <error>        ;   非 0 直接返回 ← EACCES 从这里出
...
0xffffffc0104c397c  mov w2, #0x15           ; 第二个钩子链，cap = 21 = CAP_SYS_ADMIN
0xffffffc0104c398c  blr x8                  ;   = 能力检查（HKIP 在这里才有机会介入）
```

即 **`security_sb_mount()` 先跑，能力检查后跑**。所以 EACCES 只说明 SELinux 拒绝了，
**完全没有测到 HKIP 那一道**。`hkip_check_uid_root()` 到底拦不拦 mount，目前仍然未知。

### 1.1 更糟的是：这个 mount 探针本身选错了挂载点

`mount("tmpfs", "/data/local/tmp/.cvmp", ...)` 的挂载点是 `shell_data_file`。
`security_sb_mount` 查的是挂载点目录上的 `DIR__MOUNTON`，而静态查出
`init → shell_data_file:dir` 只有 `create getattr open read search setattr` —— **没有
`mounton`**。也就是说这个探针无论能力/HKIP 如何都必定 EACCES，**它从来没有可能成功**。

正确的挂载点应当是 init 有 `mounton` 的标签，例如 `system_file:dir`
（`init → system_file:dir` 含 mounton）或 `rootfs:dir`。下一版必须换。

### 1.2 因此「借 init 域什么也拿不到」这句话要修正为

- 已知是 **SELinux 策略**在拒：`/data/adb`、`/data/user/0`、`/system/build.prop` 的
  EACCES 都来自 `avc`（`sysprop` 那条甚至有正面策略查询说应当允许，说明策略查询工具
  不可信，或以 `ctx=` 字符串为准）。
- **HKIP 那一道完全没被测到**（1.1 + 顺序问题）。
- Mate60 链的顺序是 **L4（`setuid(0)`→`commit_creds`→`hkip_update_xid_root` 置位）
  在 L5（换域）之前**。我的探针恰好反着做：先换域、探一遍、再 `setuid`。如果 HKIP
  的位置图是能力路径的第一道门，那我那遍域探针就是被自己的顺序废掉的。

下一版顺序必须是：**`setuid(0)` → 换域 → 用「init 有 mounton 的挂载点」探 mount**。

`restored sid=2130 want=2130`：借完能干净还原，不留后遗症。

### 1.1 与静态查策略的冲突

`tools\cil_query_v2.py` 说 `init → system_file:file` 有 8 项（含 open/read），
`init → system_file:dir` 有 search，`init → rootfs:dir` 有 18 项（含 mounton）。
按这个说法 `open("/system/build.prop")` 应该成功，实测却是 EACCES。

两种可能，尚未区分：

1. sid 70 其实不是 `u:r:init:s0`（读取到的 pid 1 进程可能是别的域）；
2. `cil_query_v2.py` 在 **source 侧表达式属性**上会虚报（已知它不展开
   `base_typeattr_193` 这类 `(typeattributeset A (and ...))`，之前 167 域 0 命中的
   假结果就是这么来的）。

⇒ 所以第二次探针加入了 `/proc/self/attr/current` 的**字符串**读取：数字 SID 不是
证据，域名字符串才是。

---

## 二、第二次探针（构建 `BF27238B`，160976 B）

在同一轮里同时回答两个问题：

1. **sid 70 到底是哪个域**：切之前/切之后各读一次 `/proc/self/attr/current`。
2. **HKIP 白单位图是不是真正的门**：`ROUND_SELINUX` §3.4 评价 Mate60 L4
   「`setuid(0)` 可让 `commit_creds→hkip_update_xid_root` 合法置 root 位，值得借鉴」
   —— 这条**从未实现过**。源码 `drivers_hisi_hhee_hkip_critdata.c:57-79` 说得很清楚：

   ```c
   int hkip_check_uid_root(void) {
     if (hkip_get_current_bit(hkip_uid_root_bits, true)) return 0;
     creds = current_cred();
     if (unlikely(hkip_compute_uid_root(creds) || uid_eq(creds->fsuid, GLOBAL_ROOT_UID))) {
       pr_alert("UID root escalation!\n");
       force_sig(SIGKILL, current);
       return -EPERM;
     }
     return 0;
   }
   ```

   手工写 cred 内存**不经过 `commit_creds()`**，所以这张位图里我们的位是 0；
   而 `setuid(0)` 会让内核走一次真正的 `commit_creds()` →
   `hkip_update_xid_root()` → `hkip_set_bit()`，把我们变成「合法的 root 任务」。
   （顺带纠正 `root.c` 里那句注释：它说会 `BUG`，实际源码是 `force_sig(SIGKILL)`
   + 返回 `-EPERM`，没有 `BUG()`。）

   注意 `hkip_set_bit()` 在 HVC 失败时才会 `BUG()`；`ROWM_SET_BIT` 是 TASZK 文档
   确认可用的路径，且这里是**内核自己**发的 HVC，不是我们注入的。

探针输出格式（`INIT_PROBE=1`）：

```
dom pid1 pid=<pid> tgid=<tgid> comm=<comm> osid=<o> sid=<s> own=<o>/<s> off=0 ctx=<n>:'<ctx>'
initdom sid=<s> now=<n> w=<w1>/<w2> ctx=<n>:'<ctx>' | sysprop=.. tmp=.. mp=.. mnt=..
initdom restored sid=.. want=.. ctx=<n>:'<ctx>'
hkipru setuid=<ret>/<errno> cred=<old>-><new> | sysprop=.. mnt=..
```

判读表：

| 现象 | 结论 |
|---|---|
| `ctx` 显示 `u:r:init:s0` 且 sysprop 仍 EACCES | init 真被华为策略收紧（cil 工具虚报） |
| `ctx` 显示其它域 | pid 1 那个 SID 不是 init 域，路线要换目标 |
| `ctx` 读取失败（`ctx=-13`） | 连 attr 都读不了 ⇒ SID 写到位但域更受限 |
| `hkipru setuid=0/0` 且 `mnt` 变 0 | **HKIP 白名单是门**，Magisk 路线直接打开 |
| `hkipru setuid=0/0` 但 `mnt` 仍 13 | 门是 SELinux 策略，只能走 AVC 定向毒化 |
| `hkipru setuid=-1/..` 或没打印 | setuid 路径被拒/进程被杀，路线退回 AVC |

---

## 三、体积红线（继续有效）

| 构建 | 大小 | 说明 |
|---|---|---|
| `637974FE` | 157408 | 基线（可复现，NDK r27c + `build_nop.ps1`） |
| `9E74831F` | 159768 | init 域探针 v1 |
| `B7D8EDA5` | 161120 | v2 首版，余量仅 24 B，太险，已裁 |
| `BF27238B` | 160976 | v2 定版，余量 168 B |

红线：≤161144 命中过；161272 / 161624 是 0/18。**任何改动都要盯这个数。**

---

## 四、运行纪律（本轮再次确认）

1. 起批前 `job_list` 必须空；同一时刻只跑一批。
2. push/chmod 必须在 300 s 静默等待**之前**。
3. punch 窗口内**零设备活动**（`adb` 轮询会让命中率归零）。
4. 日志长度是进度指示器：52 行= punch panic，67–70 = pipe 阶段，74+ 才进 AVC/HVC。
5. 判据必须在同一轮内打印（panic 后 pstore/logcat 都拿不到）。
