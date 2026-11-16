# 对象：管理器 App

## 功能是什么

一个能在这台华为设备上**以 root 身份跑命令**的工具，外观参照 KernelSU。装好后打开就是管理工作台的形态：
主页看会话状态与系统信息，终端页敲命令。

## 两个页面

| 页面 | 功能 | 怎么用 |
|---|---|---|
| **主页** | 会话状态（工作中/未连接）、`uid`/`domain`、已授权的调用方数量、模块数、系统信息卡（版本/内核/机型/指纹/SELinux/Seccomp） | 打开即见；顶部 ⏻ 刷新 |
| **终端** | 以 root 执行命令，保留历史，可切成"会话"模式（保留 `cd`/`env`） | 底部「终端」→ 输入 → 回车；`↑`/`↓` 翻历史，`✕` 清屏，「单次/会话」切换模式 |

## 它能干的活

- 跑任意 shell 命令（`uid=0` + 全 capabilities）
- 读写 DAC 受限但 SELinux 放行的系统路径（如 `/data/system`）
- 在 `/data/local/tmp` 放 root 属主的工具/脚本并执行
- 杀掉顽固进程、查 `/proc` 里的任意进程信息
- 长时间作业：切到「会话」模式，上下文（目录、环境变量、后台任务）会保留

## 它不干的活

装模块、改系统分区、给别的 App 一个 `su`、重启后保留 —— 这四件在这台机器上不成立，原因写在 `docs/03-selinux.md`。

## 使用前提

每次开机需要一次落地（`tools/probe.ps1`），落地后 App 可以脱离电脑使用；重启后失效，需要再来一次。

## 构建

无 Gradle 依赖，直接调用 SDK 工具链：

```powershell
.\build.ps1     # aapt2 → javac(JDK8) → d8 → zipalign → apksigner
# 产物：build/l5root.apk
```

`$env:ANDROID_SDK` / `$env:JAVA8_HOME` 可覆盖默认的 SDK 与 JDK 8 路径；
`debug.keystore` 不在仓库里，首次构建时自动生成。

## 源码

```
app/src/com/l5/root/MainActivity.java    两个页面（主页 / 终端）
app/src/com/l5/root/GatewayProvider.java Binder 网关（供别的 App 调）
app/AndroidManifest.xml                  注册 activity + provider + 权限
```
