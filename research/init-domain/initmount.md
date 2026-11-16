# TASK_INITMOUNT —— 可续跑任务单（上下文压缩后从这里继续）

> 目标（已登记为会话 goal）：打通 init 域**进程内** mount（`initmount` 动词）。
> 成功标准：`initmount tmpfs /system/usr verify=1`，且主机侧 `stat -f /system/usr` 显示 `Type: 0x01021994`（tmpfs）。
> 失败标准：三档 sid→obj→win 全部复位 ⇒ 判死，写进 `HANDOFF_2026-11-16_night.md` §7 并停止投入。

---

## 0. 当前代码状态（可直接续跑）

| 项 | 值 |
|---|---|
| 源码 | `ref\src_hwwlz\Eknight-Eutopia-GhostLock-Huawei-HWWLZ-0047e27\src\root.c` |
| 构建 | 在工作目录根执行 `.\build_nop.ps1` → `build\nop_nop_an01p\bin\preload.so` |
| 最新哈希 | **`D91FABAD`**，160,952 B（红线 161,144 B，**余量仅 192 B**，再加代码必须先删） |
| 需要的离线检查 | `llvm-readelf --dyn-syms <so>` 里除 LIBC 无 UND（删函数后必查） |
| 动词 | `srvroot`（可用、可反复）、`selfroot`、`initcfg`、`rootexec*`、`initmount`（本任务）、`grant`/`hvcroot*` |

`initmount` 请求格式（第 4 个字段是二分开关，**位置无关**，可出现在任意 token 位置）：

```
initmount tmpfs /system/usr            # 默认 win：uid0+caps+init 域+pid=0 窗口
initmount tmpfs /system/usr sid        # 只借 init 的 SELinux label，uid 保持 2000，不开窗口
initmount tmpfs /system/usr obj        # 借 label + uid0/caps，不开窗口
initmount bind /data/local/l5mnt /system/usr/l5 win   # 完整形态做 bind
```

内部顺序（v3，`D91FABAD` 起）：fork 子进程 comm=`l5mnt` → 子进程把 `'1'` 写进管道并阻塞 →
父进程 `find_task_by_comm` → **先在 EL2 uid-root 位图登记子进程 pid（srvroot 已验证顺序）** → 再改身份
（`patch_cred_sid` / `patch_cred_object`）→（仅 win）`win_open_comm` 清零 pid 并回读 → 放行 → 子进程写 `'M'`
标记 → `mount()` → 写 `'R'+{rc,errno}` → 父进程有界等待（`select` 6s）→ `win_close` 恢复 pid → 放行退出 →
父进程 `statfs`/`stat` 外部校验 → 写 `status.txt`。

**日志（v3 关键改动）**：子进程**不再写日志文件**（换域成 init 后 `/data/local/tmp` 对它不可写，g95 的
`mnt> before mount` 就是这样消失的），阶段信号全部走已存在的管道；只有父进程（uid 2000 shell 域）写
`/data/local/tmp/l5mnt.log` 并逐行 `fsync`，格式：

```
IM P1 child=<pid>
IM P2 t=<task> c=<cred> r=<real_cred>
IM P3 bit=<是否已登记>          ← 未登记且注入失败时子进程必然被打死
IM P4 patch=<1>                 ← 换身份成功
IM P5 win=<1>                   ← pid=0 窗口已开
IM P6 rel                        ← 已放行子进程
IM P7 at=<1>                     ← 子进程确实走到了 mount() 前
IM P8 n=<字节数> rc=<rc> errno=<errno>
initmount mode=… │ verify=<1>
```

判读一张日志即可完成整条二分：缺 `P4` ⇒ 死在换身份；有 `P4` 缺 `P5` ⇒ 死在开窗口；有 `P6` 缺 `P7` ⇒
子进程一醒就被 HKIP 打死（登记/窗口无效）；有 `P8` 且 `rc=-1 errno=13` ⇒ mount 被执行但被 SELinux 拒。

---

## 1. 已知实测记录（不要重复踩）

| 批次 | 构建 | 变体 | 结果 |
|---|---|---|---|
| g93 | `BF3A28F8` | v1：**子进程自己**清 pid + mount | 落地即复位，无日志 |
| g94 | `39C10BCE` | v2 win | 6 次尝试 0 落地，无判据 |
| 手动（活门） | `39C10BCE` | v2 win（在已落地的门上直接发） | **复位**，`l5r.log` 里**没有** `mnt> before mount` ⇒ 死在换域/开窗口，mount 没执行到 |
| g95 | `EE192684` | v2 **sid** | 落地后立即复位（`bootreason=abnormal`），`l5r.log` 全 NUL，无判据 |
| m1 | `D91FABAD` | v3 **win**（登记 pid → 换身份 → 开窗口 + 逐阶段日志） | 待跑 |

**结论性推断**：v2 的"没有 `mnt> before mount`"有两种可能——死在换身份，或**子进程换域后写不了**
`/data/local/tmp`（init 域对 shell_data_file 无写权限）。v3 用管道信号 + 父进程日志同时排除这两者。

---

## 2. 下一步（v3 已把日志问题修好，直接打 `win` 档一次拿全二分）

v3 的父进程逐阶段 mark+fsync 已经把"sid→obj→win 三次落地"压缩成"一次落地一张日志"，所以**不必**再按
sid→obj→win 顺序烧启动次数，直接发 `win`（默认档）即可：成功就收工，复位就看日志停在哪一行。

---

## 3. 执行步骤（按顺序，每步都要 pull）

设 `T` = 本机 transport id：

```powershell
cd <workspace>
$adb='C:\Users\Administrator\AppData\Local\Android\Sdk\platform-tools\adb.exe'
$T = (((& $adb devices -l | Where-Object { $_ -match '4EU0222111007420' }) -join ' ') -split 'transport_id:')[1].Trim()
```

（注意：设备重启后 transport id 会变，且 `-s <序列号>` 在幽灵连接时会失效，所以统一用 `-t $T`。）

### 步骤 A：拿一次落地（`win` 档，一次拿全二分）

```powershell
& $adb -t $T shell "rm -f /data/local/tmp/l5mnt.log /sdcard/Android/data/com.l5.root/files/l5/status.txt"
& '.\probe_ab.ps1' -settle fixed -fixedSeconds 60 -max 4 -tag m1 -lean -serve -noRetry `
    -reqPrefix "initmount tmpfs /system/usr" -launchPkg com.l5.root -console
& $adb -t $T pull /data/local/tmp/l5mnt.log .\probe\m1.mnt.log
& $adb -t $T shell 'cat /proc/uptime; getprop sys.boot.reason; cat /sdcard/Android/data/com.l5.root/files/l5/status.txt'
```

判读（按 §0 的日志表）：`verify=1` + 主机侧 `stat -f /system/usr` = `Type: 0x01021994` ⇒ **成功收工**。
否则按停在哪一行决定下一步：缺 `P4` ⇒ 判死；缺 `P7` ⇒ 换 `win_open`（pid 走查，不加代码，只换调用）；
`P8 rc=-1 errno=13` ⇒ 策略拒，把 `errno` 写进 HANDOFF §7 判死。

### 步骤 B（仅当 A 停在 `P6`/`P7`）：窗口无效的最后一次尝试

把 `win_open_comm(fd,"l5mnt")` 换成 `win_open(fd,(uint32_t)chm)`（老的 pid 走查版，函数已在文件里，
**体积 -0**），重新构建后再跑步骤 A。这是最后一张牌，仍复位 ⇒ 判死并归档。

---

## 4. 快捷通道（省成本）

**优先在已落地的活门上直接发请求**，不必为每个变体重新打洞：

```powershell
# 门是否还活着
& $adb -t $T shell 'cat /sdcard/Android/data/com.l5.root/files/l5/status.txt; cat /proc/uptime'
# 发请求（内容必须与上次不同）
& $adb -t $T shell "printf 'initmount tmpfs /system/usr sid 9' > /sdcard/Android/data/com.l5.root/files/l5/req.txt"
```
落地一次通常能连做 3–5 个实验；只有复位才需要重新落地。

---

## 5. 成功之后的收尾

1. 用 `bind` 验证"临时改系统"：先在 `/data/local/l5mnt` 放一个文件（`srvroot` 建目录即可），
   再 `initmount bind /data/local/l5mnt /system/usr/l5 win`，主机侧 `ls /system/usr/l5` 应看到该文件；
2. 把结论写进 `HANDOFF_2026-11-16_night.md` §7（成功版本 + 可复用命令）；
3. 明确记录"即使成功也只是本次开机临时覆盖，不是模块系统"（overlay 仍 -13，模块仍不可行）。

---

## 6. 操作纪律（今晚踩过的）

- 同一时刻只跑**一个**设备任务；`adb devices` 里若出现 `emulator-5554`，一律用 `-t` 指定真机；
- 连续 panic 后命中率显著下降（churn）：静置/冷启 10–15 分钟再跑，且用 `-max 4` 小批量；
- 每次请求后**立即 pull 日志**（复位后 page cache 可能丢）；
- 改源码前 `cp root.c root.c.<tag>`；改完先看体积（红线 161,144 B）与 UND 符号。
