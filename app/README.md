# app — 管理器

装在这台手机上、你实际会打开的那个东西。外观参照 KernelSU：主页看状态，底部切到终端敲命令。

它自己不执行命令。命令有两条路出去，App 只负责选快的那条、把结果画出来：

```
终端 / 别的 App
   ├── 快通道：Shizuku binder → RootExecService（跑在 Shizuku 的特权进程里）   毫秒级
   └── 稳通道：cmd.txt / req.txt 文件邮箱 → 门 → fork 出 uid 0 子进程         ~0.3–1 s/条
```

快通道要求设备上装了 Shizuku 且已授权（可以用 adb 拉起，也可以让门执行它的启动脚本）。拿不到就走文件邮箱——这条路只要门活着就一直可用。

## 两个页面

| 页面 | 内容 |
|---|---|
| **主页** | 会话状态、`uid` / `domain`、已授权调用方、模块位、系统信息卡（版本 / 内核 / 机型 / 指纹 / SELinux / Seccomp / Shizuku 状态）；`⏻` 刷新 |
| **终端** | 深色等宽，`$` 提示行，`↑`/`↓` 翻历史，`✕` 清屏，自动滚屏；右上角在「单次 / 会话」之间切 |

会话模式用门的常驻 shell（`shnew` / `shsend` / `shout`），`cd`、环境变量、后台任务都留着。

## 三个对外组件

| 组件 | 作用 |
|---|---|
| `MainActivity` | 两个页面 + 通道选择 |
| `GatewayProvider`（`content://com.l5.root.gateway`） | 给**别的 App** 的入口：`exec` / `ping`，权限 `com.l5.root.permission.EXEC` |
| `ShizukuProvider`（`com.l5.root.shizuku`） | Shizuku 官方提供方，服务端以 shell/root 身份把 binder 投进来 |

`RootExecService` + `IRootExec.aidl` 是塞进 Shizuku 特权进程的那一半：`exec(cmd)` 一次调用回一段输出，`uid()` / `secontext()` 供自检；
`destroy()` 保留 Shizuku 约定的 transaction code `16777114`。

## 构建

无 Gradle。需要 SDK build-tools 34 + 31、platform android-31、JDK 8（`$env:ANDROID_SDK` / `$env:JAVA8_HOME` 可覆盖）：

```powershell
.\build.ps1
# aidl → aapt2 link → javac8 → d8(含 Shizuku jar) → 塞 dex → zipalign → apksigner
# 产物：build/l5root.apk = 41,363 字节
```

`libs/` 里是 Maven Central 官方 `dev.rikka.shizuku:{api,provider,shared}:13.1.5` 抽出的 jar。
`debug.keystore` 不在仓库里，首次构建自动生成。

## 源码

```
app/src/com/l5/root/MainActivity.java      两个页面、通道选择、历史
app/src/com/l5/root/GatewayProvider.java   给别的 App 的 Binder 入口
app/src/com/l5/root/ShizukuBridge.java     Shizuku 客户端：binder 到达/死亡、授权、绑定 user service
app/src/com/l5/root/IRootExec.aidl         快通道接口
app/src/com/l5/root/RootExecService.java   在 Shizuku 特权进程里执行命令
app/libs/shizuku-*.jar                     官方 SDK 13.1.5
app/AndroidManifest.xml                    组件与权限
```

## 用之前

每次开机要在电脑上落地一次（`tools/probe.ps1`），落地后 App 就能脱离电脑用；重启后失效。
