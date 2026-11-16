# 01 · HKIP / HHEE：这层保护到底拦什么

设备：HUAWEI NOP-AN01P（NOP-AN00），HarmonyOS 4.2，kernel 5.10.43 aarch64，BL 锁。
以下"调用点"与"偏移"都来自本机 `vmlinux` 反汇编（符号表可对；地址以 `KIMAGE_TEXT_BASE + off` 形式给出）。

## 1. 检查点一览

| 检查 | 调用点 | 何时触发 | 通过条件 |
|---|---|---|---|
| `hkip_check_xid_root` | `copy_process + 0x36c` | fork / clone | `task->pid == 0` **或** 该 tid 在 `hkip_uid_root_bits` 里的位为 1 |
| `hkip_check_xid_root` | `prepare_creds + 0x17c` | exec / 改凭据 | 同上 |
| `hkip_update_xid_root` | `commit_creds + 0x2a0` | 凭据提交 | 走 `hkip_hvc4(0xC6001050)` 让 HHEE 登记 |
| `hkip_check_gid_root` | `generic_permission + 0x30` | 每次文件权限检查 | gid 字段非 0（对本项目无影响） |
| 内联判定 | `cap_capable`（`0x109b161c`） | 任何能力检查 | `pid==0` 跳过；位=1 走正常能力判定；否则若 cred 声明的 uid/suid/euid 为 0 → `printk` + `brk #0x800` |

**失败分支不是返回错误，而是故意触发的内核 BUG：`brk #0x800` ⇒ 整机复位。**
这就是"设备莫名重启"的真正原因，和踩坏内存没有关系。

## 2. `pid == 0` 是万能短路

`hkip_check_xid_root` 的第一条汇编就是：

```asm
mrs  x8, SP_EL0
ldr  w9, [x8, #0x640]     ; task->pid（华为在 task_struct 里加回的 u32 缓存）
cbz  w9, ALLOW            ; pid == 0 ⇒ 直接放行
```

- `TASK_HKIP_XID_OFF = 1600 (0x640)`，`TASK_HKIP_XID2_OFF = 1604`；
- 一个任务处于 `pid == 0` 时，fork/exec/能力检查全部放行；
- 这就是历史上"窗口"做法的来源：父进程用 physrw 把子进程的 `task+0x640` 清零，子进程做完特权动作再还原。

**注意**：清零后必须还原，否则有 pid=0 的任务长驻，`[hkip-atkinfo]` 判异常同样会拉复位。

## 3. uid 位图与 `ROWM_WRITE_8` 的真实语义

- 位图：`hkip_uid_root_bits`，按 tid 索引：`byte = tid >> 3`，`bit = tid & 7`；
- 这页被 EL2 以 ROWM 保护，**EL1 直接 store 会被静默丢弃**（写进去了、回读也在、判定却不认）；
- 唯一有效路径是内核自己的 HVC：`0xC6001050`（`ROWM_SET_BIT`）、`0xC6001054`（`ROWM_WRITE_8`）等；
- **`ROWM_WRITE_8` 的 "8" 是 8 bit 不是 8 byte**：单次只落地 1 个字节，值 `0xff` ⇒ 覆盖 **8 个连续 tid**。

实测结论（多次落地）：

```
uidbit tid=20480 at=…0a00 inj=0 rb=1/1 00->ff want=01 ok=1 word=00000000000000ff
```

- 一次注入 = 一个字节 = 8 个 tid。所以给一个进程登记时，它随后的子进程往往刚好落在这 8 个 tid 里（`hvcroot` 之后 fork 出 `/system/bin/id` 仍为 uid 0，就是这个原因）；
- 超出这个字节的新 tid 没有位 ⇒ 一旦做需要能力检查的动作就复位。

### 关于"注入是否单次有效"

早期记录（`STATE` 笔记）说"连续两次注入共用同一 victim 栈，第二次失效"。后来的实测**推翻了这条**：

```
srvroot inj=1 child=27819 cbit=1 …   ← 第一次请求
srvroot inj=1 child=30979 cbit=1 …   ← 第二次请求（又一次注入，生效）
srvroot inj=1 child=30994 cbit=1 …   ← 第三次请求（仍生效）
```

同一 boot 内三次注入全部落地。之前观察到的"第二次失败"更可能是当时设备处于 churn（连续 panic 后可靠性下降），不是注入本身的限制。
**工程结论**：每次注入后都要**回读位图确认**，不要假设成功。

## 4. 能力检查的内联判定（这条最容易被忽略）

`cap_capable` 里内联了 HKIP 判定：

```
drp  hkip_uid_root_bits          ; 位图页
pid == 0            → 跳过（放行）
bit(pid) == 1       → 走正常能力判定
否则 cred 声明 root → printk("…") ; brk #0x800
```

**含义**：一个"cred 里写着 uid=0 但 EL2 没登记"的任务，第一次需要能力的系统调用就会打死设备。
这不是策略问题，也不是我们写错内存 —— 所以任何"改 cred"的方案都必须先保证位图有位。

## 5. 由此得到的操作规约

1. 先登记位（HVC），再改 cred；
2. 改完 cred 的任务**不要立刻 fork**；要 fork 就先确认新任务的 tid 落在已覆盖的字节里（`sh`/`srvroot` 的做法：fork 后先回读子进程的位，没位就尝试一次注入，仍没有就 kill 掉，绝不制造无位 uid-0 任务）；
3. 特权动作（mount、setprop）可以由 init 域在**进程内**执行，但要套 `pid=0` 窗口；
4. 位置图写入后一律回读校验；
5. 设备复位后先看 `getprop ro.boot.bootreason`（`abnormal` = 我们触发的那类 BUG），再判断是 HKIP 还是真的踩坏了内存。
