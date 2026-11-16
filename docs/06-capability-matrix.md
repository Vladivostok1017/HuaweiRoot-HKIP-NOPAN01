# 06 · 能力对象与功能

本仓库对外提供四个功能对象。每条都在真机上验证过，用法直接给。

---

## 对象 A：门（Gate）

**功能**：一个常驻进程，替任何请求方执行命令，并以 `uid=0(root)` 身份返回结果。

**怎么用**：写命令 → 写请求 → 读结果。

```
echo 'ls -l /data/system' > /sdcard/Android/data/com.l5.root/files/l5/cmd.txt
echo 'srvroot 1'          > /sdcard/Android/data/com.l5.root/files/l5/req.txt
cat /sdcard/Android/data/com.l5.root/files/l5/out.txt
```

**返回**：命令输出（`uid=0(root) gid=2000(shell) … context=u:r:shell:s0`）
**特性**：同一 boot 内不限次数；不改调用方身份；每条命令独立进程。

---

## 对象 B：终端（App 内）

**功能**：管理器 App 的终端页，直接输入命令、看输出，支持 `↑`/`↓` 历史、清屏、
**会话/单次**切换（会话模式保留 `cd`、`export`、后台任务）。

**怎么用**：打开 App → 底部「终端」→ 输入 → 回车。会话模式点一次「单次」按钮切成「会话」。

**返回**：等宽字体输出区，自动滚动；无会话时明确显示"未连接"。

---

## 对象 C：网关（给别的 App 用）

**功能**：任何 App 通过 Binder 让门代执行命令，自己不需要 root，也不需要被提权。

**怎么用**：

```java
Bundle r = getContentResolver().call(
        Uri.parse("content://com.l5.root.gateway"), "exec",
        "id", null);
String out = r.getString("out");   // r.getInt("code")==0 即成功
```

manifest 里加一行权限：

```xml
<uses-permission android:name="com.l5.root.permission.EXEC" />
```

**返回**：`code`（0 成功 / -1 无会话）+ `out`（命令输出）。
**演示程序**：`app_demo/`（`com.l5.demo`），装上去打开就显示一条 root 命令的结果。

---

## 对象 D：研究文档集

**功能**：把"这台华为设备上保护层是什么形状"讲清楚，供镜像/内核/安全研究直接引用。

| 文档 | 提供什么 |
|---|---|
| `docs/01-hkip.md` | HKIP/HHEE 的检查点、`pid==0` 短路、uid 位图与 `ROWM_WRITE_8` 语义、`brk #0x800` 复位来源 |
| `docs/02-exploit-chain.md` | 漏洞链五个阶段 + 每阶段判据 + 落地率统计 |
| `docs/03-selinux.md` | 策略体位置、avtab 布局、桶哈希（7/7）、prmem 池结构、AVC 无效的实测 |
| `docs/04-system-image.md` | 分区枚举、块设备许可、boot/AVB/压缩格式字段表、运行时信息来源可达性 |
| `docs/05-manager-protocol.md` | 邮箱协议与全部动词、Binder 网关、会话模式 |

---

## 能力总表（一行一条，不展开）

| 能力 | 支持 | 依据 |
|---|---|---|
| 以 `uid=0` 执行任意命令并取回输出，可反复 | ✅ | 对象 A 实测 |
| 会话间保留 `cd`/`env`/后台任务 | ✅ | 对象 B 会话模式 |
| 别的 App 调用代执行 | ✅ | 对象 C 实测（`com.l5.demo` → `uid=0(root)`） |
| 创建 root 属主文件、列 `/data/system`、读 `/proc/*` | ✅ | 实测 |
| 读 `/sdcard/Android/data`（含其它 App 目录） | 仅 uid 2000 的门可读；root 子进程不可见 | 实测 |
| 读 `/data/misc`、别的 App 私有数据 `/data/user/0` | ❌ | 策略 + 实测 |
| 读 `/dev/block/*` 分区内容 | ❌ | `blk_file (getattr)` |
| `mount` / overlay / bind | ❌ | shell 域被 `security_sb_mount` 拒 |
| 改 SELinux 判定 / relabel / 装模块 | ❌ | `docs/03` |
| 持久化（重启后保留） | ❌ | 临时 root |

---

## 使用顺序

```
① 一次落地（每次开机一次，约 1/6 命中）
      .\probe_ab.ps1 -settle fixed -fixedSeconds 60 -max 6 -tag run1 `
        -lean -serve -noRetry -reqPrefix "srvroot" -launchPkg com.l5.root -console
② 落地后拔掉电脑
      对象 B：App 终端直接敲命令（可反复）
      对象 C：你的 App 调 Binder 网关
③ 重启后回到 ①
```
