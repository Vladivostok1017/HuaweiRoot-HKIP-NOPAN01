# 发现：软重启 = 我们自己的一次 post-fs-data（伪开机钩子）

日期：2026-11-16 深夜 ｜ 设备：HUAWEI NOP-AN01P（NOP_AN00，Android 12 / kernel 5.10.43）

---

## 1. 结论

**我们的门进程在软重启（restart zygote）时不会被杀**，而软重启只重启 zygote / system_server / 所有 App，
**不重启内核、不重启 init**。因此我们可以得到一次"自己触发、时机可控"的系统启动窗口：

```
1. 门（uid 2000，shell 域，常驻）→ init 域子进程做 mount / setprop
2. 门 → setprop ctl.restart=zygote        ← 触发软重启
3. 新 zygote 重新克隆 init 的 mount namespace ⇒ 新 App 一出生就能看到改动
4. 门仍活着 ⇒ 系统起来的过程中可以继续施加动作（补挂载、等 system_server、跑脚本）
```

这等价于"我们自己实现的一次 post-fs-data"，**不需要开机自启、不需要持久化**，足以支撑
"本次开机内生效的模块效果"（Magisk 语义里"改系统行为"的那一半）。

---

## 2. 它解决了什么 / 没解决什么

| 之前认为缺的 | 现在的状态 |
|---|---|
| "挂载只对之后启动的进程生效，而 App 的 namespace 早已克隆" | **解决**：软重启后 zygote 重新克隆，新 App 全部看得到 |
| "没有开机时执行的机会" | **部分解决**：有一次可重复触发的窗口，但它发生在 **init 已经启动之后** |
| init 的 `post-fs-data` 阶段（早于 zygote） | **仍然做不到**：那需要真正的开机，而我们得先有系统跑起来才能打洞 |
| 持久化 / 跨真重启 | **仍然做不到**：真重启后全部消失 |

---

## 3. 三条硬边界

1. **域**：门是 shell 域；`mount` / `setprop` 这类必须交给**借了 init SID 的子进程**（`patch_cred_sid`，uid 可保持 2000），
   且该子进程**不能 exec、不能 fork**（exec 会按 entrypoint 重算域掉回 shell，fork 会被 HKIP 打），
   `mount` 还要在 **pid=0 窗口**内做（历史 o38 实证）。
2. **窗口内通信要换地方**：软重启时 MediaProvider / sdcard 也重启，`/sdcard` 会短暂不可用
   ⇒ 门在这个窗口里应当读 **`/data/local/tmp`** 的邮箱，而不是 `/sdcard/Android/data/<pkg>/files/l5`。
3. **一次性**：真重启后一切消失，需要重新打洞（现在约 1/4 命中/次开机）。

---

## 4. 这条能力能支撑的"模块"类型

| 类型 | 是否可行 | 依赖 |
|---|---|---|
| root 脚本类（清理、调参、改文件） | **现在就能** | `srvroot` 命令通道 |
| 属性类（型号、density、feature 开关） | 大概率可行 | init 域 `setprop`（`initcfg` 已写好，需泛化成任意属性名） |
| 文件替换类（hosts、库、字体） | **待验证** | init 域 mount + `context=<系统标签>` + 软重启 |
| 内核模块 / 真实 sepolicy 改写 / 依赖开机早期时序 | **不可行** | `MODULE_SIG_FORCE`、无 kprobes、无持久化 |

### 文件替换的实现思路（Magisk magic mount 的手工版）

overlayfs 被策略拒（实测 `-13`），但"合并"可以在 init 域子进程里用 bind 手工拼：

```
1. bind 真实 /system/etc → /system/usr/orig_etc        （先把原目录暴露到一个可见位置）
2. mount tmpfs（context=u:object_r:system_file:s0）→ /system/etc
3. 遍历 orig_etc，逐项 bind 回 /system/etc              （保留原有内容）
4. 把模块要覆盖的同名文件 bind 上去                     （实现"合并 + 覆盖"）
5. setprop ctl.restart=zygote                          （软重启，让新 App 看到）
```

第 2 步的 `context=` 是关键：bind/tmpfs 出来的文件若保留**来源标签**（`shell_data_file` 等），
消费方（App、netd 等）多半没有读它的 allow，会 EACCES。带系统标签的挂载才能真生效。

---

## 5. 待验证的三件事（一次落地可验证前两件）

1. `mount` 带 `context=u:object_r:system_file:s0` 是否被策略放行；
2. `setprop ctl.restart=zygote` 是否被 init 域放行、软重启是否成功；
3. 软重启后新 App 是否真的看到替换内容（`adb shell stat -f /system/etc`、`ls -Z`、`cat` 验证标签与内容）。

对应代码改动（都很小）：

- `initcfg` → 泛化成 `setprop <name> <value>`（当前写死 `persist.adb.tcp.port`）；
- `initmount` → 增加 `ctx <label>` 形式（给 tmpfs/bind 带 `context=`）。

---

## 6. 与"模块"产品形态的关系

如果接受"**不需要开机自启、不需要持久化**"，那么管理器可以提供这样的"一次性模块"：

```
模块目录： <name>/
            files/…            要覆盖进 /system 的文件（保留相对路径）
            props.txt          要设置的属性
            apply.sh           额外 root 脚本
点击"应用" → 门执行：挂载/属性/脚本 → 软重启 → 本次开机内生效 → 真重启后消失
```

这**不是**兼容市面 Magisk 模块（那些依赖开机时序、`/data/adb`、模块脚本钩子、以及 sepolicy 改写），
但它是这台机器上"改系统行为"的唯一可行形态，且完全建立在已经验证过的原语之上。

---

## 7. 顺带确认：静默安装（不经过系统安装界面）

我们的门是 `uid 0 + shell 域`，而 **shell 身份本身就被系统豁免了安装确认**：
`pm install` / `cmd package install` 走 PackageInstaller session，shell 不会弹安装界面。
实测见 `adb shell pm install -r /data/local/tmp/<x>.apk`（同 uid 2000，等价于门在做）。

- 能：静默安装 / 卸载 / 启用停用 / 授予运行时权限 / `am force-stop` / `appops`。
- 不能：把 App 装成**系统应用**（需要写 `/system/priv-app` + 重新扫描 + 签名匹配，本机 erofs+verity 不可能）、
  也不能绕过 APK 签名校验或安装到别的用户（本机单用户）。
