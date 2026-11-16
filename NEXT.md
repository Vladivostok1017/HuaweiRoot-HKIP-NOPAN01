# 接下来：这份工作停在哪，后面怎么接

作者已经停止推进。代码、研究材料、失败记录全部在仓库里，以 GPL-3.0 开放。

下面写清三件事：**哪些已经验证过、下一步做什么、哪些不要再花时间**。目的是任何人拿到一台同型号机器就能接着往下做，不用重走前面撞过的墙。

---

## 一、已验证可用的部分

| 能力 | 状态 | 证据 |
|---|---|---|
| 以 `uid=0` 跑任意命令，同一 boot 内不限次数 | 可用 | `srvroot` 连续 5 次均为 `uid=0(root)`（`probe/ab_summary.csv`） |
| 会话 shell（保留 `cd`/环境变量/后台任务） | 可用 | `shnew` / `shsend` / `shout` |
| 第三方 App 通过 Binder 借 root | 可用 | `app_demo`（`com.l5.demo`）→ `uid=0(root)` |
| 门进程在软重启（`restart zygote`）中存活 | 已确认 | [`research/notes/soft-reboot-hook.md`](research/notes/soft-reboot-hook.md) |

---

## 二、下一步：三件事，按投入产出排序

### 1. 把「软重启钩子」打通（最小、最值钱）

软重启只重启 zygote / system_server / 所有 App，内核与 init 不动，而门不会被杀。
于是有了**一次可自己触发、时机可控的系统启动窗口**——等价于自己实现的 `post-fs-data`。

代码只差一点：`root.c` 的 `initcfg` 目前把 key 写死成 `persist.adb.tcp.port`，泛化成 `setprop <name> <value>` 就能写 `ctl.restart=zygote`。

验证方式（一次落地内完成）：

```
initcfg ctl.restart zygote
→ 观察 system_server 重启（pidof system_server 变化）
→ 软重启后新 App 是否继承了新的 mount namespace
```

注意窗口内 `/sdcard` 会短暂不可用（MediaProvider 也在重启），这个窗口里门要读 `/data/local/tmp` 的邮箱。

### 2. 文件替换类「一次性模块」

overlayfs 被策略拒（实测 `-13`），但在 init 域子进程里可以手工 bind 拼出「合并 + 覆盖」：

```
bind 真实 /system/etc → /system/usr/orig_etc
mount tmpfs (context=u:object_r:system_file:s0) → /system/etc
逐项 bind 回 orig_etc；再 bind 模块的覆盖文件
setprop ctl.restart=zygote
```

`context=` 是关键——挂载出来的东西如果带着来源标签（`shell_data_file` 之类），消费方没有读它的 allow，会 EACCES。

对应改动：`initmount` 增加 `ctx <label>` 形式。完整流程见 [`research/notes/soft-reboot-hook.md`](research/notes/soft-reboot-hook.md) §4。

### 3. 模块产品形态（App 侧）

```
<name>/
  files/…        要覆盖进 /system 的文件（保留相对路径）
  props.txt      要设置的属性
  apply.sh       额外 root 脚本
```

App 上一个「应用」按钮：挂载 / 属性 / 脚本 → 软重启 → 本次开机内生效，真重启后消失。
这不是兼容市面 Magisk 模块（那些依赖开机时序、`/data/adb`、脚本钩子、sepolicy 改写），但这台机器上「改系统行为」只有这一种形态可行。

---

## 三、改动成本的实际约束

- **尺寸**：`preload.so` 红线 **161144 字节**，当前 **158808** 字节 ⇒ 只剩约 2.3 KB。
  新功能要么精简旧代码，要么拆到 `su_daemon`（独立进程，不受这条红线约束）。
- **落地**：每次开机一次，单次约 3 分钟，成功率波动很大（历史 1/6 ~ 1/4，连续 panic 后会掉到 0，见 `probe/ab_summary.csv`）。所有后续实验一旦落地就全在手机上做，不需要电脑。
- **一次落地验不完**：一次 boot 内可以把上面 1、2 都试掉，3 留着迭代。

---

## 四、不要再花时间的部分

这些是实测撞出来的墙，不是推测。逐条依据都在 `docs/` 与 `research/`：

- **KernelSU 那套内核模块** —— `MODULE_SIG_FORCE=y`，且 `# CONFIG_KPROBES is not set`。
- **改真正的 sepolicy** —— 策略体与 avtab 在 EL2 只读内存池里；`HKIP_HVC_RO_MOD_UNREGISTER` 只接受 EL2 注册过的**精确** `(va,size)`，猜范围会让设备复位（实测两次）。
- **分区 dump** —— shell 域对 `blk_file` 只有 `getattr`，`dd` 直接 EACCES，与 uid 无关。
- **把 App 装成系统应用** —— 要写 `/system/priv-app` + 重新扫描 + 签名匹配；本机 erofs + verity。
- **跨真重启持久化** —— 没有 `/data/adb`，也拿不到早于 zygote 的时序。

---

## 五、怎么开始

```powershell
.\payload\build.ps1        # 门
.\app\build.ps1            # 管理器
.\tools\probe.ps1 -settle fixed -fixedSeconds 60 -max 6 -tag run1 `
  -lean -serve -noRetry -reqPrefix "srvroot" -launchPkg com.l5.root -console
```

脚本打出 `e2e status written` 就是落地了，之后拔线。

阅读顺序建议：`README.md` → `docs/06-capability-matrix.md`（能做什么）→ `research/notes/soft-reboot-hook.md`（下一步）→ `docs/02-exploit-chain.md`（链条为什么不换）。

有结果或有疑问，开 issue 即可。
