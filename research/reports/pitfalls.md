# 四个开源项目的踩坑记录 → 我们代码的对应关系

参考：HWWLZ（nova6 5.10.43，母本）、JoinChang/ghostlock-oneplus（6.1）、
IonStack-S22U（三星 5.10.226，`ref/s22u/MEMORY.md`，坑记得最细）、KSuRoot。

S22U 的最后状态是 **成功**（`MEMORY.md` §4g 是成功设备日志），所以它的坑表最值得照抄。

---

## 一、S22U 的坑（按他们的编号）

### §4b 已解决 — 回收失败是因为 BUDDY 把释放页拆了

- 泄漏的 mm slab 正确 DISCARD 到 `free_area[3]` 之后，**一次 order-0 PCP 补充会把它拆成 8 个 order-0 页**，
  被 `copy_pte_range`/`handle_pte_fault` 等吃掉，于是 skb 回收到的永远是**别的页**
- 修复：`prefill_order0_buddy()` —— `close(memfd_leak)` 之后、drain 之前 mmap/touch/munmap **16MB**

**我们的状态**：✅ 有 —— 日志 `mm order0 prefill bytes=16777216`

### §4d 已解决 — 回收 miss 导致 stale `misc.fops` → `die@misc_open`

三处修复：
1. **buddyinfo 驱动的 absorb**：每 pair 读 `/proc/buddyinfo`，把 zone Normal 的 `free_area[3]` 抽到接近空
   （target 0、cap 4096 页 / 768 pair），让释放页落在近乎空的链表头部
2. **hold-all、从不关闭的批次**：回收 send 保持排队不 drain（`SKB_DRAIN_SENDS=1` 才回到 drain 循环），
   64 个 8-pair 环，只在绕回时关闭一个批次
3. **真正的窃贼**：write-watchpoint 抓到第一个写者是
   `clear_page ← kernel_init_free_pages ← kmalloc_order ← tracing_open ← do_sys_openat2`
   —— **是他们自己 `track_mm_page()` 的 tracefs open** 把页吃掉的

**我们的状态**：
- ⚠️ absorb 退化了：日志 `mm order3 absorb: buddyinfo unreadable, filling to cap`
  （本机 `/proc/buddyinfo` 被 SELinux 拒），只能"填到上限"，没有 target 0 的精度
- ✅ hold-all：`skb reclaim hold-all sent=24/24 pairs=8`
- ⚠️ 他们遇到的"自己人偷页"这类问题，我们没法用 watchpoint 复现（无 gdb）

### §4e — pipe phys gate 读到 `slab_cache=0`

- gate 用 phys-read 读 `page->slab_cache`(+0x18) 得到 0
- 两个候选原因：(1) §4c 的读地址换算错；(2) skb frag 页**本来就不是 slab 页**，
  `slab_cache` 合法为 0，除非管道页回收把那页放进了 slab

**我们的状态**：5.10 分支**整个 gate 被 stub 掉了**（直接放行），所以看不到这个诊断

### §4f 已解决 — CFS 路径 payload 被"自己的 printf"撕裂

- 64 次 STAMP 都命中了 `pi_blocked_on`，但 TRIG dump 里是帧垃圾
- 写者不是调度器：那个槽位上是 `file_tty_write` 的栈帧记录
- 真凶：他们在 stamp 循环之后、`g_consumer_go=1` 之前加的
  `pr_warning("stamp: %d/%d setsockopt failed...")` —— 这次**控制台 write() 重入内核，
  落在 waiter 自己的栈上**，把 payload 撕掉
- **HARD INVARIANT：最后一次 stamp 到 park 之间禁止任何系统调用，连 printf 都不行**

**我们的状态**：❗**高风险**。我们的 `pipe.c`/`fops.c` 在那段窗口里 `pr_info` 非常密：

```
consumer enter seq=1 tid=...
consumer fire tid=... nice=18 calls=0
consumer kick pselect tid=... tkill=0 errno=0
consumer punch tid=... ret=0 errno=0 nice=18
pselect returned attempt=1 ...
```

其中 `consumer kick` / `consumer punch` 两条紧贴 punch 动作，如果它们的 `write()` 落在
waiter 栈上，就会解释为什么我们有约 40% 的未命中，以及为什么命中后偶尔仍会崩。

---

## 二、§4c 与 VMEMMAP 常量（重要，已回退）

S22U 的结论：

- 真实 vmemmap（含 memstart 的正确公式）`= 0xfffffffefde00000`（他们 memstart=0x80000000）
- `target.h` 里那个 `0xfffffffeffe00000` 比它**高 0x2000000** = `(memstart>>12)*0x40`
- `pipe.c` 的 va→page **漏掉 memstart**：pfn 多 0x80000 → page 多 0x2000000
- **两者正好抵消** ⇒ 对 `pipe.c` 而言那个常量是等效正确的

我们的 `pipe.c:392` 用的正是 `qemu_wrap_linear_to_page`（注释明写 "Do not add memstart_addr"），
memstart=0x40000000 ⇒ allowance `0x01000000`。

**结论：`VMEMMAP_START` 必须保持 `0xfffffffeffe00000`。**
我曾按 arm64 宏把它改成 `0xfffffffe00000000`，破坏了抵消，导致改完立刻崩 —— 已回退并加了警告注释。

他们同节的告诫：**不要单独"修"这个常量，也不要单独给 pipe.c 补 memstart**，两者要一起动。

---

## 三、我们当前与他们的差距（按价值排序）

| 差距 | 来源 | 影响 |
|---|---|---|
| 1. 关键窗口内的 `pr_info` | S22U §4f | 可能造成未命中与偶发崩；改动最小、收益直接 |
| 2. `buddyinfo` 被拒 → absorb 无目标值 | S22U §4d-1 | order-3 吸收不精确，回收命中率下降 |
| 3. 5.10 分支的 cache gate 被 stub | S22U §4e | 少了"这页是不是 pipe slab"的判据，只能靠事后扫描 |
| 4. pipe 环没落进 `page_base` 那块 | S22U §4b/§4d | 当前 `found=0` 的直接原因 |

## 四、下一步（按成本/收益）

1. **删掉 pselect 临窗的 pr_info**（S22U §4f 的硬不变量）—— 零风险、可能直接提高命中率
2. 给 `find_pipe_buffer` 加**进程内重试**：没命中就重新 `alloc_pipe_object` 一批再扫，
   一次运行覆盖十几次回收（避免每次赌 45 秒重启）
3. absorb 在 `buddyinfo` 不可读时改用固定更大的上限，或改从 `/proc/pagetypeinfo`
   之外的 `zoneinfo` 推断（本机 `zoneinfo` 可读）
4. 恢复 cache gate 的等价判据：不读 `struct page`（vmemmap 经 copy_to_user 会 abort），
   改为"扫到的槽位是否 `ops==anon_pipe_buf_ops`"，作为提前失败信号
