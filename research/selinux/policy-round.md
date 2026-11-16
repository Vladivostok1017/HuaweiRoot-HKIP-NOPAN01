# SELinux 绕过路线 —— 阶段存档（2026-11-11）

承接 `ROUND_C_TERMINATION_2026-11-10b.md`（Route C 收尾攻关）。本文只记录
**SELinux 绕过**这一条主线的全部结果，包括两条路线各自的结论、依据、以及未完成的部分。

---

## 零、一句话结论

| 路线 | 结论 |
|---|---|
| ① 清 HKIP 判据字节 `*(selinux_state+8)` | **结构性不可行**（所在池为 `RO_NO_RECL`，内核没有解保护路径），实测两次注入成功后写仍 panic |
| ② 借 app 身份（uid+gid+SID） | **机制已验证**（读别人 cred、写自己 cred 全部成功、无 panic）；功能判定目前为负（`EACCES`），但**极可能是路径选错**（`/data/data` 是软链），已改为同时测 `/data/user/0`，尚未跑出结果 |
| ③ 改 `selinux_state.initialized`（同族设备 W29 的已验证方案） | 该方案作用于另一份内核；本机开关是 ① 指的那个 prmem 指针字节，不是 `initialized` |
| ④ CVE-2025-48543 | **不适用**（ART 用户态 UAF，给的是 system_server 级代码执行，不是内核原语，也过不了 MLS） |

---

## 一、路线 ①：判据字节 —— 结构性关闭（含源码级证明）

### 1.1 目标确认（静态，本机反汇编）

`security_compute_av` = `0xffffffc0109da654`：

```asm
0xffffffc0109da6ac  ldr   x9, [x0, #8]            ; x9 = *(selinux_state+8)，是指针
0xffffffc0109da6b0  cmn   x9, #1                  ; == -1 直接退出
0xffffffc0109da6b8  mov   x10, #-0x200000000
0xffffffc0109da6bc  movk  x10, #0x87ff, lsl #16   ; 下界 0xfffffffe87ff0000
0xffffffc0109da6c0  cmp / b.lo                    ; 越界即退出
0xffffffc0109da6c8  mov   x11, #-0x1ffffffff
0xffffffc0109da6cc  add   x10, x9, #1
0xffffffc0109da6d0  movk  x11, #0x8fff, lsl #16   ; 上界 0xfffffffe90000000
0xffffffc0109da6d4  cmp / b.hs
0xffffffc0109da6dc  ldarb w9, [x9]                ; 读它指向的字节
0xffffffc0109da6e0  tbnz  w9, #0, normal_policy   ; bit0=1 → 正常策略查询
0xffffffc0109da6e4  mov   w8, #-1
0xffffffc0109da6e8  str   w8, [x19]               ; avd->allowed = 0xffffffff
0xffffffc0109da6ec  b     out                     ; 直接返回
```

`x0` 是参数传入的 `struct selinux_state *`（该函数内无任何 `adrp`）。要清的是
**`*(selinux_state+8)` 指向的那个字节**，不是 `selinux_state+8` 这个指针字段
（曾误写指针字段，会把指针最低字节从 `0xf8` 改成 `0x00`，让检查读同页错误字节，已移除）。

补充静态证据（全镜像扫描 `[selinux_state, +0x70)`，共 154 处访问，
脚本 `tools\state_access2.py`）：

- `selinux_state+0x08` 是**指针字段，被 SELinux 代码读取 60+ 次**（`ldr xN,[xN,#0x70]`）；
- `selinux_state+0x48` 是另一个热指针 = avc（与 `target.h: SELINUX_STATE_AVC_OFF 0x48` 一致）；
- `get_selinux_enforcing` = `0xffffffc0109f1360`：`mov w0, #1 ; ret` —— 常量桩，
  与 `ref\hw\got_w29_TECHNICAL.md` 所述「`/sys/fs/selinux/enforce` 读路径编译成常量 1
  （上游行为，不是华为桩）」互相印证。

### 1.2 实测：两次注入都成功，写仍然崩

构建 `9AED878B`（160488 B），`round2` 批第 4 次命中：

```
hvc nd[0] p=fffffffe98013fd0 w0=ffffffea66950000 w8=0 st=fffffffe87ff0000 sz=0x1000
hvc pol pool=ffffffea66950000 want=fffffffe87ff0ff8 n0=... hit=... cnt=1
hvc gate p=fffffffe87ff0ff8 v=01 rd=1 page=fffffffe87ff0000
unreg armed pid=26791 op=c6001033 a1=fffffffe87ff0000 a2=0000000000001000
unreg done consumed=1
rw    armed pid=26796 op=fffffffe87ff0000 a1=0000000000000001 a2=0
rw    done consumed=1
                       ← 之后没有 hvc gate-after，进程死在数据写那一步
```

即：`hkip_unregister_ro_mod(0xfffffffe87ff0000, 0x1000)`（HVC 0xC6001033）与
`set_memory_rw(0xfffffffe87ff0000, 1)` 都通过注入器执行成功（`consumed=1`），
随后对判据字节的普通数据写仍然 panic，字节维持 `0x01`（bit0=1）。

### 1.3 根因：这个池不可解保护（源码级）

`drivers_hisi_hhee_mm_prmem.c`：

```c
static inline void lock_range(int (*fn)(...), unsigned long base, size_t size)
{
        set_prmem_ro(base, DIV_ROUND_UP(size, PAGE_SIZE));   /* EL1 页表 → 只读 */
        (*fn)((void *)base, size);                            /* EL2 → hkip_register_ro */
}

static void unprotect_range(const unsigned long start, const unsigned long size)
{
        if (is_pool_type_wr_recl(type))      unlock_range(hkip_unregister_rowm_mod, ...);
        else if (type == PRMEM_POOL_RO_RECL) unlock_range(hkip_unregister_ro_mod, ...);
        else return;                          /* ← RO_NO_RECL 没有解保护路径 */
}
```

池布局（`ref\nop_syms.txt`，每个 pool 0x68 字节）：

| 符号 | 地址 | 偏移 | 类型 |
|---|---|---|---|
| `__start_data_prmem_pools` = `selinux_prot_pool` | `0xffffffc0136d0000` | `0x36D0000` | **ro_no_recl（不可解）** |
| `selinux_pool` | `0xffffffc0136d01a0` | `0x36D01A0` | **ro_recl（可用 0xC6001033 解）** |
| `__end_data_prmem_pools` | `0xffffffc0136d0208` | `0x36D0208` | — |

判据字节所在页 `0xfffffffe87ff0000` 属于 **`selinux_prot_pool` 的唯一节点**
（实测 `st=fffffffe87ff0000 sz=0x1000`），即 `RO_NO_RECL` ⇒ 无论发什么 HVC 都解不开。
这同时解释了此前三种 ROWM 写法（`ROWM_WRITE_8` 0xC6001054、`ROWM_CLEAR_8` 0xC600105A、
`ROWM_REGISTER` 0xC6001040 + `ROWM_WRITE_8`）为何全部**静默拒绝**（链正常返回、
无 panic、字节不变）：ROWM 系列要求区间本身以 ROWM 类型注册。

> **纠错**：TASZK 走的是 `selinux_pool`（ro_recl），不是 `selinux_prot_pool`。把
> `SELINUX_PROT_POOL` 当作目标从一开始就不成立。

### 1.4 附带确定的两条地址类事实

1. `pipe_phys_read_data/write_data` 由 `is_direct_ptr()` 门禁，其白名单锚定在
   **链接期** `KIMAGE_TEXT_BASE`（`0xffffffc010000000`）。KASLR slide 后运行时镜像
   落在窗口之外（例：`0xffffffe93d73b068`）⇒ 一律拒绝（实测 `rd=0 wr=0`）。
   受保护的 SELinux 数据只能用 `kernel_read_data`/`kernel_write_data`（configfs 路径）。
2. prmem 的 vmap 影射地址（`0xfffffffe87ff0000`）同样被 `is_direct_ptr()` 拒绝
   （实测 `rd=0 wr=0`），必须走 KIMAGE 别名或 configfs 路径。

---

## 二、路线 ②：借 app 身份 —— 机制通了，功能判定待定

### 2.1 设计依据

- app 数据隔离靠 **MLS 约束**：`(mlsconstrain (dir (read getattr search)) (or ... (dom l1 l2) ...))`，
  app 数据在 `s0:c512,c768`，而 `shell`/`system`/`init` 全在 `s0` ⇒ **借「域」没用**，
  只有带相同 level 的身份才行 —— 也就是**那个 app 自己的 SID**。
- 本机 `CONFIG_HKIP_PROTECT_CRED` 未开（TASZK 原文亦确认）⇒ `cred->security` 是普通
  kmalloc 对象，改 uid/gid/sid 是**纯数据写**，不需要 EL2、不需要解保护。
- 源码自带的注意事项：`root.c` 的 `ids[]` 注释写明
  「gid=2000 so /data/local/tmp (0771 shell:shell) is group-writable **without
  CAP_DAC_OVERRIDE, which Huawei HKIP still blocks even with pid=0**」
  ⇒ 用 uid=0 去开 `0700` 的 app 目录会先死在 DAC，轮不到 SELinux。这正是要**连 uid 一起借**的原因。

### 2.2 实测记录

**(a) 只借 SID（uid 仍为 0）** —— 构建 `C973E416`（156960 B）：

```
borrow app=com.tencent.mm comm=com.tencent.mm pid=12322 osid=70 sid=2081 own=2131/2131
borrow-open /data/data/com.tencent.mm fd=-1 errno=13
root cred patched uid=0/0 gid=2000/2000 sid=2131/2131
```

**(b) 完整借身份（uid+gid+SID）** —— 构建 `BC8A0742`（157120 B）：

```
borrow app=com.tencent.mm comm=com.tencent.mm pid=12677 osid=70 sid=2113 own=1983/1983
borrow-open /data/data/com.tencent.mm fd=-1 errno=13 uid=10240 idok=1 idwr=1
```

即：读到 WeChat 的 cred（`osid=70 / sid=2113`）与其 `uid=10240`，把
`{uid,gid}×4` 与 `{osid,sid}` 都写进自己的 cred（`idok=1 idwr=1`，无 panic），
但 `open("/data/data/com.tencent.mm")` 仍 `EACCES(13)`。

> 注：`sid=2131`/`1983` 是 shell 自己的 SID，随开机不同；`asid` 与 `own` 不一致属正常。

### 2.3 最可能的原因：路径软链

`/data/data` 是历史软链，其父目录是 `system_data_file`，**app 域通常没有它的
`search` 权限**；app 访问自己数据走的是 `/data/user/0/<pkg>`。这与之前的静态分析
（`/data/data` 被拒时真正的 tsid 可能是 `system_data_file` 而非 `app_data_file`）一致。

因此下一步的判定改为**同时测两条路径**，并加上「写入后回读自己 SID」的自证：

- 构建 `2DE80C0F`（157296 B）：+ 回读 `now=<sid>` 与 `patch_cred_sid` 返回值 `s1/s2`；
- 构建 `637974FE`（157408 B，当前）：+ 同时测 `/data/user/0/<app>`。
  日志格式：
  ```
  borrow-open <app> fd=%d errno=%d uid=%u idok=%d idwr=%d sid=%u now=%u s1=%d s2=%d | user0 fd=%d errno=%d
  ```

`now` 的判读：若 `now == 借来的 sid` 而两条路径都 `EACCES` ⇒ 身份正确但 SELinux 仍拒；
若 `now != sid` ⇒ SID 写没生效，问题在写原语而非策略。

### 2.4 尚未观测到的部分

`2DE80C0F` 与 `637974FE` 都还没跑到借身份阶段（见 §四 churn 记录），
所以 `now=` 与 `/data/user/0` 的结果**目前未知**。

---

## 三、文档级对照（这是本轮最重要的方法论收获）

### 3.1 `ref\hw\got_w29_TECHNICAL.md`（同族华为内核，真机验证过）

- `CONFIG_SECURITY_SELINUX_DEVELOP` 未开 ⇒ `selinux_state` 无 `enforcing` 字段，
  `/sys/fs/selinux/enforce` 读成常量 1 —— **与本机反汇编完全吻合**。
- 其放行点是 **`selinux_state.initialized`（+2）叶零写** ⇒ `security_compute_av()`
  直接 `allowed=0xffffffff`；同时需零写 `avc_cache.avc_cache_threshold`。
  真机复跑记录：attempt 1 通过、两个叶写 `ok=1`、退出码 0。
- **但本机不适用**：本机 `selinux_state[0..8)` 实测全为 0，且开关是
  `*(selinux_state+8)` 那个 prmem 指针字节（§1.1）。每台机器 `__randomize_layout`
  排布不同，不能照搬偏移。
- 该文档还记 `policydb.permissive_map`（mrx 风格）按 **type** 置位，评价「一般不如
  `initialized` 路线」，且写原语写不出任意小整数 startbit。

### 3.2 TASZK `hypervisor1`（labs.taszk.io/articles/post/hypervisor1/）

- HVC 派发 `(x0>>24)&0x3f == 6 → prmem_handler`，**没有任何调用者身份校验**。
- `hkip_uid_root_bits` 等位图用 `ROWM_REGISTER` 注册，可用 `ROWM_SET_BIT` 置位。
- `ss_initialized` 是 `__wr`（ROWM），重载 policy 不实用。
- SELinux 绕过路径：**先改 AVC cache（"this is not protected memory"），再
  `HKIP_HVC_RO_MOD_UNREGISTER` 解 `selinux_pool`，然后改受保护的 policy 条目**。
  —— 这印证了我们的 AVC 负结果：毒化 AVC 单独不够。
- 其 `protect_vmap_area` 只调用 HKIP，**没有 EL1 `set_prmem_ro`**；本机较新内核多了
  这一层，所以「只解 EL2」在本机必然失败（§1.3）。

### 3.3 impalabs `2212_huawei-security-hypervisor`

HHEE 会**处理并可能否决内核页表写入**（"Kernel Page Table Writes"、"Stage 2 faults
during stage 1 page table walk"）。这解释了为何即便调 `set_memory_rw` 也可能无效。

### 3.4 Mate60 Pro 链路逐级评估

| 层 | 他们的做法 | 对本机 |
|---|---|---|
| L1 perf 泄 TextKaslrOffset | perf 侧信道 | 可选改进（我们 tracefs+KernelSnitch 能用但需 5–17 次重试） |
| L2/L3 触发+布荷 | CVE-2026-43499 + sigreturn 伪帧/fpsimd 512B | 同 CVE、不同布荷；我们 pselect 版本已打通 |
| L2' 8B 写 | `rb_erase` | 一致 |
| L2b 读写台 | `misc.fops` → ashmem 假表（configfs read/write_bin） | **完全一致**（`ASHMEM_MISC_FOPS`+`CONFIGFS_READ_ITER`+`CONFIGFS_BIN_WRITE_ITER`） |
| L4 凭据 | 只有 `cap_effective(+0x38)` 可写，靠 `setuid(0)` 走合法路径 | **约束不适用**（本机 cred 可直接写）；但 `setuid(0)` 可让 `commit_creds→hkip_update_xid_root` 合法置 root 位，值得借鉴 |
| L5 借域 | `cred->security→sid = u:r:init:s0` | 思路采纳，但 **MLS 使任何 s0 域都读不了 app 数据**；改成借**目标 app 自己的 SID** |
| L6 su 网关 | App 通道 spawn | 正交，我们已有 su daemon |

### 3.5 CVE-2025-48543 评估

- 性质：**Android Runtime (ART) 用户态 UAF**（CWE-416），描述为
  "escape chrome sandbox to attack android system_server"，影响 Android 13–16，
  已列入 CISA KEV，补丁在 `platform/art`。
- 对本机**不适用**：给的是 system_server 级用户态执行，不是内核原语；我们已经拥有
  内核任意读写 + uid 0；且落到 `system` 域仍在 `s0`，一样过不了 MLS。
- 参考：<https://source.android.com/security/bulletin/2025-09-01>、
  <https://cve.circl.lu/vuln/CVE-2025-48543>

---

## 四、设备侧产出率与操作纪律（本轮踩过的坑）

### 4.1 体积红线（硬约束）

同一设备、零轮询条件下：

| `preload.so` 大小 | 结果 |
|---|---|
| ≤ 161144 | 命中过 HVC/注入器阶段（含 159080 / 160232 / 160488 / 156960 / 157120） |
| 161272 / 161624 | **0/18，punch 稳定失效** |

当前构建 157408 ✓ 有余量。任何改动都要盯住这个数。

### 4.2 运行纪律

1. **启动批前必须 `job_list` 确认为空**；同一时刻只跑一批。
   本轮又犯了：`pwsh-1` 已打印 `PROBE DONE` 但 pwsh 进程未退，我随后起了新批，
   两批同时打同一台设备。
2. `push`/`chmod` 必须在「300 s 静默等待」**之前**完成（否则 punch 窗口被破坏）。
3. 运行期**零设备活动**（`adb` 轮询会让 punch 0/40）。
4. `pstore` 对 shell 是 Permission denied（panic 重启后无 root）⇒ 崩溃 `pc/lr` 拿不到；
   `logcat` 也会随重启丢弃 ⇒ **判据必须在同一轮内打印出来**。
5. churn 会显著压低 punch：连续 panic 后命中率下降；应静置/冷启后小批量（3–4 轮）。

### 4.3 本轮失败分布（供估算成本）

| 批 | 构建 | 结果 |
|---|---|---|
| probe ×4 | 9AED878B | 3 panic + **1 命中注入器**（两次注入 consumed=1） |
| probe ×4 | C973E416 | 1 cfi → 借 SID（errno=13）；1 panic；2 未跑（被误杀） |
| probe ×4 | BC8A0742 | 2 cfi（1 到借身份，uid=10240 仍 13）；1 panic |
| probe ×4 | 2DE80C0F | 3 panic + 1 timeout，0 命中 |
| probe ×4 | 637974FE | 尚未运行 |

即「到达借身份阶段」约 **1/4 ~ 1/2**，一次判定通常需要 1–2 批。

---

## 五、构建清单（本轮）

| SHA256 前缀 | 大小 | 内容 |
|---|---|---|
| `9AED878B` | 160488 | 靶子改为 `*(selinux_state+8)`、pool 改 `selinux_prot_pool`、写 0 |
| `C973E416` | 156960 | 停用死掉的判据字节路线；只借 SID（uid 仍 0） |
| `BC8A0742` | 157120 | 完整借身份（uid+gid+SID） |
| `2DE80C0F` | 157296 | + 回读自身 SID 与 `patch_cred_sid` 返回值 |
| `637974FE` | 157408 | + 同时测 `/data/user/0/<app>`（当前） |

---

## 六、诚实未验项

1. `now=`（借 SID 后回读值）**从未观测到** —— 无法判定「写没生效」还是「SELinux 仍拒」。
2. `/data/user/0/<pkg>` 的测试**尚未运行**。
3. 若两条路径都被拒，仍不知道拒绝来自 SELinux 还是 HHEE 的额外钩子；AVC 原文未能捕获。
4. `selinux_pool`（ro_recl，**可解保护**）上的可行改写目标尚未确定：policy 的
   `allow_unknown` 所在节点在遍历中未命中（遍历器仍有镜像窗口误判的 bug，已记录在
   `ROUND_C_TERMINATION_2026-11-10b.md` §7.4）。
5. 借来的身份只能访问**被借 SID 那个 app** 的数据，不是全局放行 —— 若目标是「读所有
   app 数据」，仍需回到「关掉判定路径」那一类方案（本机对应 ①，已判死）。
