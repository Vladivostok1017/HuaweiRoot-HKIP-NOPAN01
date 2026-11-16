# 04 · 系统镜像与分区：能拿到什么、拿不到什么

这一节是"研究"里最有价值的部分之一：即使不 root，也能从本机读出大量结构信息；而真正的镜像级读取，
被 SELinux 对块设备的许可卡住。

## 1. 分区表：可读

```bash
adb shell ls -l /dev/block/by-name
# lrwxrwxrwx 1 root root 16 … batt_tp_para -> /dev/block/sdd15
# lrwxrwxrwx 1 root root 16 … boot        -> /dev/block/sdd57
# lrwxrwxrwx 1 root root 16 … cache_block_device / bfm_block_device …
adb shell ls -ldZ /dev/block /dev/block/by-name
# drwxr-xr-x 7 root root u:object_r:block_device:s0  /dev/block
```

- 目录是 `0755`，**普通 shell 就能列全部分区名与指向**（本仓库的 `docs` 数据即由此取得）；
- 设备节点本身是 `brw------- 1 root root`（如 `sdd57`），DAC 上只有 root 能开；
- 标签：多数是 `block_device`，个别是 `cache_block_device` / `bfm_block_device` / `userdata_block_device` 等。

## 2. 分区读数：被 SELinux 卡住（不是 DAC）

即便拿到 uid 0：

```bash
dd if=/dev/block/by-name/boot of=/data/local/tmp/bt.bin bs=4096 count=1
# dd: /dev/block/by-name/boot: Permission denied
```

策略里 shell 域对块设备只有 **getattr**：

```
(allow shell dev_type (blk_file (getattr)))
```

对比能读的域：`e2fs` / `fsck` 对 `userdata_block_device`、`metadata_block_device` 有 `open read write`；
`init` 对多数块设备只有 `relabelto`，只有 `swap_block_device` 有读写。
⇒ **分区 dump 在这套能力下不成立**，也不需要 SELinux 域以外的解释。

## 3. 镜像结构（研究用，来源于公开设备的镜像分析）

这些是 boot 镜像分析里必须掌握的字段；做镜像研究时按此顺序解析：

| 结构 | 关键字段 | 备注 |
|---|---|---|
| **AOSP boot header v0–v2** | `magic "ANDROID!"`、`kernel_size`、`ramdisk_size`、`os_version`、`header_version` | 结构随 header_version 变化，必须先读版本 |
| **vendor boot** | `VNDRBOOT` magic、`vendor_ramdisk_size`、`dtb_size`、`page_size` | 与 boot 分离，常见于 GKI 设备 |
| **init_boot** | header_version 4 | ramdisk 单独成区 |
| **boot signature (AVB)** | `AVB0` magic、`rollback_index`、`flags`、`release_string` | verity/AVB 校验的入口 |
| **分区类型** | `ext4` / `erofs` / `f2fs` superblock magic | `/system` 在本机是 erofs + verity |
| **压缩格式** | gzip / lz4 / lz4_legacy / zstd | ramdisk 常为 lz4；注意 lz4 的 legacy 与 frame 两种 |
| **补丁格式** | bsdiff / puffdiff（`PUF1`）/ zucchinidiff | 差分包里 puffdiff 与 bsdiff 不通用 |

上表是从公开的 boot 镜像工具链（以及第三方临时 root App 里内嵌的提取器）归纳的字段顺序，
用于镜像研究时定位；本机 `boot` 分区能否读到，取决于上一节的许可。

## 4. 内核与运行时信息来源（可达性实测）

| 目标 | 可达性 | 说明 |
|---|---|---|
| `/proc/version` | ✅ | 内核版本字符串 |
| `/proc/kallsyms` | ✅（符号名可见） | 本机用它导出 213k 条符号，用于反汇编对照 |
| `/proc/iomem` | ❌ | App 与 shell 域都读不到（`proc_iomem` 未授权） |
| `/proc/vmallocinfo` | ❌ | uid 0 + shell 域仍 Permission denied |
| `/sys/fs/selinux/policy` | ❌ | 同上（策略体只能通过内核里读出来的方式获取） |
| `/dev/block/by-name` | ✅（仅列表） | 见第 1 节 |
| `/dev/block/*` 内容 | ❌ | 见第 2 节 |
| `getprop` / `Build.*` | ✅ | 指纹、版本、机型 |
| `/sys/fs/selinux/enforce` | ❌（App 读不到） | 注意：读失败 ≠ 宽容，别把失败当结论 |

## 5. 给镜像研究者的两条实用建议

1. **先建立符号与偏移的对照表**：本机有 `vmlinux`（可提取）时，`/proc/kallsyms` 与镜像符号做双向核对，
   比在运行时盲猜偏移可靠得多；本仓库所有 `0x…` 偏移都是这样来的。
2. **区分"镜像里的"与"运行时的"**：`.bss` 段不在镜像文件里（`swapper_pg_dir`、`memstart_addr`、
   `vmap_area_list` 都属于这类），用文件级读取（如 configfs 路径）读它们**恒为 0** —— 这一条曾浪费过整整一轮。

## 6. 待补

- [ ] `super` 分区内的逻辑分区布局（`/dev/block/by-name/super` 的 lpmetadata）
- [ ] AVB 描述符逐项解析（`avbtool info_image` 的等价实现）
- [ ] erofs + verity 的实际只读验证路径
- [ ] 把上面第 3 节的字段表整理成可执行的解析脚本（`tools/bootimg.py`）
