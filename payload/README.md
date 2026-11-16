# payload

这里是"门"。

一个 aarch64 共享对象 `preload.so`，被塞进管理器 App（`com.l5.root`）的进程里。
它从用户态打穿到内核栈，拿到"按物理地址读写"的能力，然后把**自己所在的这个进程**变成一个服务进程：
一个目录里放几个文本文件，它读命令、执行、写回结果。App、Binder 网关、本仓库的脚本，全都是这个协议的客户端。

编译：

```powershell
.\build.ps1
# → build\nop_nop_an01p\bin\preload.so            要注入的镜像
# → build\embed\su_daemon_aarch64_pie             落地后释放的 root 服务进程
```

`-Ndk` 或 `$env:ANDROID_NDK` 指定 NDK 根目录。
`preload.so` 存在尺寸红线 **161144 字节**，超过就装不进去（当前构建 158808 字节）。

## 源码分工

| 文件 | 职责 |
|---|---|
| `src/main.c` | 入口 `run_exploit()`：等系统进入安静窗口、装致命信号处理器（崩溃前把阶段落盘）、按阶段推进整条链 |
| `src/slide.c` | 泄漏内核基址、算 KASLR slide；提供 `fd_set` 的读写原语（`slide_pselect_*`） |
| `src/pipe.c` | `pipe_buffer` 塑形 + 物理内存原语：把 `copy_to/from_user` 升级成按物理地址整页读写 |
| `src/fops.c` | CFI 劫持点：把 `ashmem` 的 `file_operations` 换成自己的，之后一次 `ioctl` 就是"进内核执行我的函数"；`hvc_*` 封装 EL2 调用 |
| `src/root.c` | 门本体：邮箱循环 + 全部动词（`srvroot`/`selfroot`/`sh*`/`initcfg`/`hvcroot*`/`grant`，见 `docs/05`）；`find_task_by_comm`、`patch_cred_identity`、`hkip_zero_pid_for_seq` 等 |
| `src/util.c` | 底层工具：kernelsnitch 初始化、futex 原语、日志、内嵌镜像的落盘 |
| `src/preload.c` | 落地后把内嵌的 `su_daemon` 释放到目标位置并拉起来 |
| `src/su_daemon.c` | 独立进程：socket 服务，收命令 → fork/exec；`hkip_prepare_exec` 处理 exec 前的 HKIP 前置条件 |
| `src/targets/nop_nop_an01p/target.h` | 本机全部偏移（NOP-AN01P / kernel 5.10.43）。换机型只动这里 |
| `src/common.h`、`offset.h`、`layout.h`、`hkip_gate.h` | 结构布局、内核对象偏移、HKIP 许可窗口定义 |
| `src/kernelsnitch/` | futex 桶哈希探测的上游头文件 |
| `src/buddyinfo_check.c`、`fd_budget_check.c`、`layout_check.c` | 三个独立校验程序，单独编译成 ELF 在设备上跑，用来验证结构假设而不是靠猜 |

## 尺寸红线为什么存在

注入点的可容纳上限是 161144 字节，这是实测出来的硬边界。
`root.c` 里被删掉的旧动词（`enforce`、`mount`、`avtgo2` 等）不是"觉得没用"，是那些路已经被实测否掉，留着只会把镜像顶过红线。

## 和上游的关系

骨架来自 GhostLock 的 HWWLZ 分支；这个目录是它在 NOP-AN01P 上适配后的版本——
本机偏移、HKIP 位图语义、邮箱协议、`srvroot` 与会话模式都是后加的。出处与许可见 [`../CREDITS.md`](../CREDITS.md)。
