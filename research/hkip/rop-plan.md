# HKIP 解除 SELinux 只读（PRMEM RO_MOD）— 设计与静态事实

依据：TASZK《Don't Believe The Hype(rvisor)》<https://labs.taszk.io/articles/post/hypervisor1/>
与公告 <https://labs.taszk.io/blog/post/95_hw_hypervisor_bp/>（覆盖 P40 / MatePad Pro / **Mate 40**，华为未修、无 CVE）。

## 0. 为什么必须这样做（结论）

- 华为把 SELinux 的分配改为 PRMEM pool：`pmalloc(&selinux_pool, …)`，pool 由 vmap area 组成，
  并在 **EL2** 用 `HKIP_HVC_RO_MOD_REGISTER` 标为只读；`ss_initialized` 是 `__wr`；
  `hkip_uid_root_bits` / `hkip_gid_root_bits` 用 ROWM 保护。
- ⇒ **从 EL1 直接写策略/相关变量不会生效**（stage-2 只读，与 guest 页表无关）。
  这解释了本项目的两个现象：`configfs_write` "成功"但无效果；母本"hkip 保护 selinux，关不掉"。
- 解除只读的唯一已知路径：在**内核上下文**里调用
  `hkip_unregister_ro_mod(pool_va_start, pool_va_size)`（或等价 HVC）。

## 1. 本镜像内已静态确认的符号 / 常量

| 项 | 值 | 依据 |
|---|---|---|
| `hkip_unregister_ro_mod` | `0xffffffc0122085b0` | 符号表 |
| HVC id `RO_MOD_UNREGISTER` | `0xC6001033` | 该函数内 `mov w0,#0x1033; movk w0,#0xc600` |
| HVC id `RO_MOD_REGISTER` | `0xC6001032` | `hkip_register_ro_mod` 同法 |
| `hkip_hvc4` / `hkip_hvc` | `0xffffffc01000dbe0` → `b hkip_hvc_dispatch` | 符号表 |
| `__hyp_set_vectors` | `0xffffffc010003de0`；`hvc #0; ret` 在 `0x…3de8`、`0x…3df4` | 符号表 + 字节模式 `0200 00d4 c003 5fd6` |
| `selinux_prot_pool` | `0xffffffc0136d0000`（结构长 0x208） | `prmem_protect_pool` 内 `adrp/add #0x0`、`#0x208` |
| pool 结构 | `pmalloc_list` 在 **pool+0x8** | `ldr x20,[x19,#0x8]` |
| vmap_area_node | `next` +0x8、`va_start` +0x10、`va_size` +0x18 | `ldr x20,[x20,#0x8]` / `ldp x1,x2,[x20,#0x10]` |
| 注册要求 | start、size 必须 4K 对齐，否则 `brk #0x800` | `tst x8,#0xfff; b.ne brk` |

`hkip_unregister_ro_mod(x0=start, x1=len)` 内部即 `hkip_hvc4(0xC6001033, start, len, …)`，
所以 ROP 只需把 x0/x1 设好并跳到该函数（不必自己拼 HVC）。

## 2. Gadget 清点（我们的镜像，非 TASZK 的偏移）

| 用途 | 地址 | 备注 |
|---|---|---|
| `blr x8; ldp x29,x30,[sp,#0x10]; add sp,sp,#0x20; ret` | 8 处：`0xffffffc01008d49c`, `0x…096e88`, `0x…0a9a44`, `0x…0aa5c0`, `0x…0aa62c`, `0x…0acaa8`, `0x…0ebb28`, `0x…119d78` | 字节模式已核 |
| 基础指令密度 | `mov x8,x0` 2441 / `blr x8` 13233 / `ldp x29,x30,[sp],#0x10` 18526 / `ldr x8,[sp,#0x10]` 1734 / `ldp x0,x1,[sp,#0x10]` 仅 2 处 | 用于后续拼“装参 + 装 x8” |

待定：①“从栈装 x0,x1 后返回”的 gadget（候选 2 处，需反汇编确认收尾）；
②“从栈装 x8 后返回”的 gadget（1734 处候选中筛）；③链尾安全落点（`eret`/`finish_ret_to_user` 类）。

## 3. 执行上下文：为什么不需要页表遍历

ROP 链要写在内核**栈**上，而内核栈属于**线性映射**：`task->stack` 可读，
pipe 原语可直接读写（`copy_page_to/from_iter` 是内核↔内核拷贝，不过 usercopy）。

策略（比 TASZK 更省，因为他们靠逆向得到固定偏移）：

1. 选一个**我们自己可控唤醒时机**的进程（如 su daemon 阻塞在 `accept4`，或自己的线程阻塞在 `read`）。
2. 用原语**整段读取它的内核栈**（16KB），在栈上**搜索已知返回地址**（例如进入 `__sys_accept4` /
   `inet_csk_accept` 的 LR），从而定位到将要被 `ldp x29,x30,…` 弹出的那一帧 —— 无需猜测深度。
3. 把链写进该帧（保存的 x29/x30 及其后的高地址区域，均为栈上数据，可写）。
4. 触发该进程返回（连接 socket / 写 pipe），链在内核态执行：
   `x0 = node.va_start`、`x1 = node.va_size` → `hkip_unregister_ro_mod` → 返回链尾安全落点。
5. 之后回到既有的 data-only relax（`policy+0x254` bit1 置 1，`map.mapping` 指向全零页），
   这次写入才会真正生效（stage-2 已解除只读）。

## 4. 与现有代码的关系

- `selinux_relax_policy()`（`src/root.c`）保留：解除只读后它就是可用的最后一步。
- 池信息读取：`selinux_prot_pool`(+0x8 → node → +0x10/+0x18)，全部是镜像/线性地址，
  用 `kernel_read_data`（configfs）即可，无需特殊原语。
- 一旦 SELinux 解除，`su -c` 的 shell 域应能访问 `/data/data` 等，可用 `/data/local/tmp/chk.sh` 验证。

## 5. 风险与回退

- 写栈若命中错误帧 → 目标进程崩溃（不涉及内核全局状态）；选择“自己可控的进程”可把风险限制在自身。
- `hkip_unregister_ro_mod` 对未注册范围调用可能返回错误（-ENOTSUPP / -524），不致命。
- 每次失败最多损失该进程；不影响已获得的 uid=0 root。
