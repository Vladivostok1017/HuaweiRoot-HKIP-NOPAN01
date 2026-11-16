# 03 · SELinux：本机策略的真实形状，以及为什么"改判定"走不通

本机 `# CONFIG_SECURITY_SELINUX_DEVELOP is not set` ⇒ `struct selinux_state` **没有 enforcing 字段**，
`get_selinux_enforcing` 被编译成 `mov w0,#1; ret`。所以"关掉 SELinux"这个动作在内核里不存在，
只能改判定数据本身。下面是这条路上每一段实测。

## 1. 策略体在哪

```
selinux_state.policy = 0xfffffffeafff0d80      ; vmalloc，每轮稳定
&policydb->te.avtab  = policy + 0x138          ; context_struct_compute_av: add x25,x8,#0x130 邻域
  htable @ +0x00   node**（从 selinux_pool 分配 ⇒ ROWM）
  nel    @ +0x08   = 82330
  nslot  @ +0x0c   = 32768
  mask   @ +0x10   = 0x7fff
avtab_node 步长 0x20：key@+0x00（4×u16 {src,tgt,cls,spec}）| datum@+0x08 | next@+0x10
链按 (src,tgt,cls) 升序；比较到 cls 时 b.lo 提前返回 ⇒ 插入必须保序
```

读取用 `kernel_read_data`（configfs 路径），不要用 `root_read_data`：后者在 `cfg_fallback_enabled=0` 时不会回落 configfs。

## 2. 桶哈希（7/7 命中，可复现）

`avtab_search_node` 里的 mixer，逐条转写时最容易搞错的是 **ARM `BFXIL` 语义**：

> `BFXIL Wd, Wn, #lsb, #width` 是把 `Wn[lsb+width-1:lsb]` 抽出来插到 **Wd 的低端**，不是同位偏移。

改正后用 7 个真实 `(bucket,key)` 样本验证 7/7：

```
(311,3543,98)→0  (1480,2122,8)→1  (821,1680,14)→2  (1588,1622,8)→3
(1432,2698,11)→4 (1398,1207,98)→5 (1396,2561,10)→6
常数 c1=0xcc9e2d51 c2=0x16a88000 c3=0x1b873593 c4=0xe6b26000
     c5=0xe6546b64 c6=0x85ebca6b c7=0xc2b2ae35
输入 tc=key[+4], tt=key[+2], st=key[+0]；bucket = hash & mask
```

C 版本已内联进 payload，并在设备上**自检**（3 个样本不过就不写）；Python 回归脚本在 `probe/fit3.py`。

## 3. 目标元组与本机 type 值

```
shell=1385   misc_user_data_file=602   system_data_file=526   init=820   class(dir)=7
(1385,526,7) → bucket 12963
(1385,602,7) → bucket 29820
```

> 曾有一个流传的数字 `bucket=4273`：穷举 5 个 type × 14 个 class、外加 6 种字段排列，**没有任何元组能落在 4273**。
> 结论：桶号必须由已验证的哈希算出来，不能记"我读过的那一桶"。

## 4. 为什么最终写不进去（两条独立原因）

### 4.1 avtab 页在 EL2 只读池里，写即复位

```
直写 avtab 节点页（不发任何 HVC） → fsync 日志停在 "nounreg write pk=…"，随后 bootreason=abnormal
```

所以 `HKIP_HVC_RO_MOD_UNREGISTER` 是必需的，不是可选的。

### 4.2 拿不到 EL2 注册的精确 `(va,size)`

`hkip_register_ro_mod(va,size)` 只做 4K 对齐检查，然后 `hkip_hvc4(0xC6001032, va, size)` —— **EL1 侧不留副本**。
可读来源逐个排除：

| 来源 | 结果 |
|---|---|
| `selinux_pool` 的 pmalloc 链（5 池 × 12 槽全扫） | 只有 5 个区间，都不覆盖 avtab 页 |
| `vmap_area_list`（`KIMAGE+0x3AB7610`） | 在 `.bss`，configfs 读回 0 |
| 池节点 `va` 字段 | 不是 `vmap_area`（解出来是 text 指针） |
| `master_lock+0x18` 的 prmem 区间树 | 读不到（同样落在不可读区） |
| 猜测/推导区间 | g58、g69 两次复位 |

`RO_MOD_UNREGISTER` 对**未注册的区间**不是无害的：直接复位。所以没有"试几次找到对的"这条路。

### 4.3 AVC 缓存放行无效

全量污染 583/583 节点（`confirmed == wrote`）后，uid 0 的 shell 域进程访问 `/data/data` 仍然是 `13`。
结合 4.1/4.2 可知：本机的判定**不取该缓存**，改缓存没有意义。

## 5. 池结构（顺便纠正一处广为流传的误解）

```
selinux_prot_pool = KIMAGE + 0x36D0000   ; 数组基址，__start_data_prmem_pools
每个 prmem_pool 结构 0x68 字节；selinux_pool = +0x1A0 = 第 5 个（index 4），0x68×5 == 0x208
```

- 所以"单个池结构 0x208 字节"是**误读**，0x208 是数组总长；
- 池结构里可确认的字段：`+0x08` pmalloc 链、`+0x30=0x1000`（页大小）、
  `+0x38=0x800000`（`CONFIG_HKIP_SELINUX_POLDB_SIZE_MB=8`）、`+0x40/+0x48=0x5e3000`（已用）；
- `selinux_prot_pool`（第 0 个）是 `RO_NO_RECL`：**没有解保护路径**，任何 HVC 都解不开；
  `selinux_pool` 是 `ro_recl`（可用 `0xC6001033` 解）。

## 6. 策略原文里几条决定架构的许可

```
(allow shell dev_type (blk_file (getattr)))                    ← 分区读不了
(allow init property_type (property_service (set)))            ← init 域能 setprop
(allow init base_typeattr_469 (filesystem (mount remount …)))  ← 469 = (fs_type \ debugfs)
(allow init system_file (dir (mounton)))  (allow init system_data_file (dir (mounton)))
(allow init system_data_file (file (read write …)))            ← /data/system 可读写
(allow init shell_data_file (dir (search)))                    ← 只能穿过，不能读文件
(allow init shell_exec (file (read getattr map execute open))) ← init 能 exec sh
(allow shell shell_data_file (file (… create write execute …)))
(neverallow appdomain dev_type (blk_file (read write)))
```

**由此推出的双域架构**（不是设计偏好，是唯一解）：
文件 I/O 交给 shell 域一半；`mount`/`setprop` 这类只能 init 域做，而且必须**在进程内**做（exec 会按 entrypoint 重算域、掉回 shell；fork 会被 HKIP 打死）。

## 7. 还能走的路（留档）

- `policydb` 的 `permissive_map` / `allow_unknown` 与 avtab 在同一受保护池 ⇒ 同样卡在 4.2；
- B 路线（改 sidtab 里某个 sid 的 `type`）只需 4 字节，但要先确认 sidtab 是否也在 `selinux_pool`；
- 如果哪天能拿到 EL2 注册区间（例如从 HHEE 侧，或找到 prmem 真实链表布局），A 路线是通的：定位、哈希、桶链、保序覆盖节点的算法都已验证。
