# 05 · 管理器协议

门的协议非常简单：**一个目录里的三个文件** + 一个 Binder 网关。所有上层（终端、Binder、脚本）都走同一套。

## 1. 文件邮箱

目录：`/sdcard/Android/data/com.l5.root/files/l5/`

| 文件 | 作用 |
|---|---|
| `cmd.txt` | 要执行的命令（`srvroot` 读取） |
| `req.txt` | 请求动词。门**逐字比较**它与上一次的内容，只有变化才处理 |
| `out.txt` | 门的输出（门每次请求先 truncate，再写） |
| `status.txt` | 会话状态（`session=up` / `uid=` / `domain=` / `srvroot=1` …） |
| `callers.txt` | 调用过 Binder 网关的包名（首页"超级用户"计数来源） |

**去重规则带来的协议要求**：每次请求的 `req.txt` 必须与上次不同。
最省事的做法是把唯一性放在**动词名后面的空格数**上（各 handler 都会跳过前导空格），
不要往命令正文里塞 token（会污染 shell 语法）。

## 2. 动词

| 动词 | 说明 | out.txt |
|---|---|---|
| `srvroot` | fork 一个子进程 → 登记 EL2 位 → 只改子进程 cred（uid 0，域 shell）→ `exec sh -c $(cat cmd.txt)` | 子进程的输出 |
| `selfroot` | 门**自己**改成 uid 0（一次性，之后 `/sdcard` 立刻不可读） | 自检行 |
| `rootexec` | 门自己升级并**不 fork**，直接执行 `cmd.txt`（`selfroot` 的完成形态，只适合一次性的收尾动作） | 命令输出 |
| `rootexec2` | 门**已经**是 uid 0 时的执行器：fork → 回读子进程的位（缺了就补一次注入，补不上就 kill）→ 放行 | 子进程的输出 |
| `shnew` | 起常驻 root shell（FIFO + 会话日志） | `patch=` / `bit=` |
| `shsend <cmd>` | 往常驻 shell 写一行 | 不写 |
| `shout <off>` | 读会话日志自 `off` 起的增量 | `next=<新偏移>` + 数据 |
| `shkill` | 关会话 | — |
| `initcfg [port]` | 借 init 域**在进程内** `setprop`（如 `persist.adb.tcp.port`） | 结果 |
| `hvcroot <tid>` | 给任意 tid 登记位 + 改 cred（不做 capability 检查的任务才安全，见 docs/01 §3） | 结果 |
| `hvcrooti <tid>` | 同上，额外把 pid 1 的 sid 拷过去（进 init 域；该域可 mount，但没有可执行 entrypoint） | 结果 |
| `grant <pid>` | 按 tgid 找到任务 → 登记位 → 改 cred（面向"别的 App 想借 root"） | 结果 |

`srvroot` 是日常主用动词，也是唯一"可反复、不冒险"的形态。
`rootexec` / `selfroot` 会让门自己变成 uid 0，代价是门随即看不见 `/sdcard`（FUSE 按 uid 分视图），通道随之变聋——所以它们只用于单次收尾，不作为常驻形态。

## 3. 时序（一次 `srvroot`）

```
app:  rm out.txt
app:  write cmd.txt          命令
app:  write req.txt          "srvroot <唯一后缀>"
gate: 读到 req.txt 变化 → 打开 cmd.txt → fork → 登记位 → 改子进程 cred
gate:  子进程 dup2(out.txt) → execl(sh -c 命令)
app:  轮询 out.txt（≤20 s）→ 显示
```

判据：`out.txt` 里出现 `uid=0(root)`。

## 4. Binder 网关（让别的 App 调用）

`app/src/com/l5/root/GatewayProvider.java`，authority `com.l5.root.gateway`：

```java
Bundle r = getContentResolver().call(
        Uri.parse("content://com.l5.root.gateway"), "exec",
        "ls -l /data/system", null);
String out = r.getString("out");   // r.getInt("code") == 0 表示成功
```

- 方法：`exec`（arg=命令）、`ping`（返回 `up`）；
- 权限：自定义 normal 权限 `com.l5.root.permission.EXEC`，调用方 manifest 里声明即可；
- 串行：门一次只处理一条请求，Provider 内部加锁排队；
- **Android 12 起的坑**：目标 App 被 `force-stop` 后其 provider 对外不可见，调用会报
  `IllegalArgumentException: Unknown authority`。管理器必须处于运行状态。
- 演示调用方：`app_demo/`（`com.l5.demo`）。

## 5. 会话模式（保留上下文）

`srvroot` 每条命令都是新的 `sh -c`，没有上下文。需要 `cd`/`export` 时用会话：

```
shnew                → 门 mkfifo /data/local/tmp/.l5sh.fifo
                       门自己 O_RDWR 打开（避免 open 竞争 + 不让 shell 读到 EOF）
                       fork → 登记位 → 改 cred → dup2(fifo,0) dup2(log,1,2) → exec sh
shsend cd /data/system
shout 0              → 取回 "cd 的回显+后续输出"，返回 next=偏移
shsend pwd           → 仍然是 /data/system
shout <next>
```

终端页的「会话 / 单次」开关就是切这两个模式。

## 6. 安全边界（写进设计的部分）

- 门**不改自己的身份**（否则 `/sdcard` 的 FUSE 视图立刻失效，通道变聋）；
- 任何新任务在被放行前都要**回读 EL2 位**，没位就 kill，绝不制造"无位 uid-0 任务"；
- `force-stop` 的管理器不再响应（这是 Android 行为，不是 bug）；
- 会话 shell 的孙进程如果需要能力检查，仍然要求 tid 有位（见 docs/01）。
