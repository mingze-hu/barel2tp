# barel2tp

[English](README.md) | 简体中文

一个 Rust 编写的 macOS/Linux 裸 L2TPv2 客户端。它不调用系统 VPN 框架，也不启动 `pppd`、`xl2tpd`；程序自身实现 L2TPv2、PPP LCP、CHAP-MD5、IPCP 和 IP 数据转发。

程序只把配置中的 IPv4 网段指向自己创建的 TUN，因此适合只需访问远端少量内网网段、又不能或不想使用系统 VPN 配置的场景。

## 安全边界

裸 L2TP 没有加密、完整性保护或可靠的对端身份认证。CHAP-MD5 只用于验证 PPP 用户，不会加密用户名之外的会话流量，也不能保护 L2TP 数据包。请仅在可信网络、已有的安全传输层或明确接受该风险的环境中使用。

本实现会拒绝 PAP、MS-CHAP 和非 MD5 的 CHAP 算法，避免认证方式被静默降级。

## 已实现

- L2TPv2 SCCRQ/SCCRP/SCCCN 和 ICRQ/ICRP/ICCN 会话建立
- L2TP 控制消息序号、ZLB 确认、重复报文处理和指数退避重传
- 主动 L2TP HELLO 保活、失效检测和控制报文目标校验
- 带序号及不带序号的 L2TP 数据通道
- PPP LCP 双向协商、运行期 LCP/IPCP 重协商和 Echo 响应
- RFC 1994 CHAP-MD5 Challenge/Response 及运行期间再认证
- PPP IPCP IPv4 地址协商；可选请求主、备 DNS 地址
- macOS `utun` 和 Linux `/dev/net/tun`
- 自定义 IPv4 网段路由，并在目标网段包含 VPN 服务器时固定外层服务器路由
- Ctrl-C、SIGTERM/SIGHUP 和错误退出时清理程序添加的路由
- 可选的后台运行：`--daemon` 脱离终端，`--status` 查看状态，`--stop` 优雅停止，`--cleanup` 回滚异常退出留下的路由（仅 macOS/Linux）

当前只支持 IPv4、单隧道、单 PPP 会话，不支持 L2TP 隧道级共享密钥、IPv6、IPsec、MPPE、压缩、多链路 PPP，也不会修改系统 DNS。

## 构建

需要较新的稳定版 Rust：

```bash
cargo build --release
```

命令行二进制支持以下平台：

| 操作系统 | TUN 后端 | 运行权限 | 额外要求 |
| --- | --- | --- | --- |
| macOS | 内核 `utun` | `sudo` | 无 |
| Linux | `/dev/net/tun` | `root` 或 `CAP_NET_ADMIN` | `iproute2` |

复制示例配置并修改：

```bash
cp config.example.toml config.local.toml
export BAREL2TP_PASSWORD='你的口令'
```

也可以不设置口令环境变量，程序会从当前控制终端无回显读取口令。该方式在 `sudo` 下同样使用原始终端，不会把口令放进命令行参数。

先做无副作用的配置检查：

```bash
./target/release/barel2tp --config config.local.toml --check
```

## 运行

macOS 配置 utun 地址和路由通常需要管理员权限：

```bash
sudo --preserve-env=BAREL2TP_PASSWORD \
  ./target/release/barel2tp --config config.local.toml
```

Linux 可以用 root 运行，也可以按部署环境给二进制授予 `CAP_NET_ADMIN` 并确保当前用户能打开 `/dev/net/tun`：

```bash
sudo setcap cap_net_admin+ep ./target/release/barel2tp
./target/release/barel2tp --config config.local.toml
```

用 `-v` 查看协商状态，用 `-vv` 查看逐帧日志。也可以用 `RUST_LOG` 覆盖日志级别。

### 后台运行

`--daemon` 让进程在隧道建立后转入后台并脱离终端，仅 macOS 和 Linux 可用：

```bash
sudo ./target/release/barel2tp --config config.local.toml --daemon
```

前台命令会一直等到隧道真正就绪才返回 0 并提示日志位置；连接失败时返回 1，并直接指出该看哪个日志文件，不会留下“启动成功”的假象。

没有显式指定时，运行日志和 PID 文件都放在**可执行文件所在目录**，对应上面这条命令就是 `target/release/barel2tp.log` 和 `target/release/barel2tp.pid`。选它而不是家目录，是因为后台运行通常要 `sudo`，家目录会变成 `/var/root`，日志反而不好找。`--log-file`、`--pid-file` 可以各自换到别处，相对路径按**启动时**的工作目录解析。

查看状态：

```bash
./target/release/barel2tp --status
```

停止：

```bash
sudo ./target/release/barel2tp --stop
```

`--status` 打印进程状态、两个文件的位置和日志末尾三行，进程不在时退出码为 1，方便脚本判断。`--stop` 发送 SIGTERM 并等到进程真正退出（最多 15 秒）才返回，也就是说它返回时路由已经清理完毕。两条命令都不读配置文件、不需要口令；它们默认去可执行文件所在目录找 PID 文件，启动时用过 `--pid-file` 的话这里要带上同一个路径。

其余要点：

- 口令在转入后台之前读取，交互输入和 `--password-stdin` 都能照常使用；转入后台后标准输入接到 `/dev/null`
- 日志以 0600 权限追加写入，`route`、`ip` 等子命令的输出也会一并落盘；文件不会自动轮转，长期运行请交给 `newsyslog` 或 `logrotate`
- PID 文件用文件锁阻止重复启动，进程退出时自动删除；被强杀留下的陈旧文件不会妨碍下次启动。它以 0644 写入，`--status` 因此不需要 `sudo`
- 除了 `--stop`，SIGTERM、SIGHUP 和 Ctrl-C 也都会先清理路由再退出；`kill -9` 跳过清理，事后用 `--cleanup` 回滚
- 后台进程的工作目录是 `/`，`--config`、`--log-file`、`--pid-file`、`--control-socket` 的相对路径都在启动时解析为绝对路径
- 前台运行完全不受影响：不指定 `--log-file` 就照常打到终端，也不会写 PID 文件

### 异常退出后的清理

`kill -9`、进程崩溃或断电时，程序来不及回滚路由。后台运行因此会把装过的每一条路由记进状态文件（默认 `barel2tp.state`，与日志同目录），事后精确回滚：

```bash
sudo ./target/release/barel2tp --cleanup
```

`--status` 发现进程不在、状态文件还在时会主动提示，并给出一条可以直接照抄的清理命令。清理需要管理员权限，并且会先确认后台进程确实没在跑——否则就把正在用的路由删掉了；两项检查任何一项不过，状态文件都原样保留。

TUN 接口消失时内核通常会自动清掉指向它的网段路由，所以真正会留下来的是**指向物理网关的服务器 `/32` 固定路由**（只有业务网段包含 VPN 服务器地址时才会添加）。这条残留会让你换网络之后连不上服务器。`--cleanup` 会把「系统里已经没有这条路由」和「真的删不掉」分开报告：前者是常态，后者才是问题，可以用 `netstat -rn` 复核。

记录不会因为一次清理就凭空消失：

- 只有确实删除失败的条目会留在状态文件里，排除原因后再跑一次 `--cleanup` 就能重试；有条目失败时命令以退出码 1 结束
- 状态文件先写临时文件再改名，中途断电最多留下一个临时文件，不会把记录截断成读不出来的半截 TOML
- 上次异常退出还没回滚的记录会被下一次运行继承下来，不会被新会话的记录覆盖掉
- 记录里带着系统启动标识。重启之后路由表本来就是空的，而 `utun` 名字会被别的隧道复用，这时 `--cleanup` 直接把记录作废，不会照着旧账去删别人的路由

前台运行默认不写状态文件，避免往 `.app` 这类只读目录里写东西；需要这层保护就显式加 `--state-file`。

## macOS 图形应用

仓库同时包含一个原生 SwiftUI 菜单栏应用，适用于 macOS 13 及以上版本。窗口按「先必填、后可选」分成五个分区：

| 分区 | 内容 |
| --- | --- |
| 概览 | 连接开关、当前状态、缺哪些必填项 |
| 连接设置 | 服务器与账户；协议参数收在独立的「高级选项」面板里 |
| 内网网段 | 哪些网段走 VPN，逐行即时校验写法 |
| 通用 | 菜单栏图标、关窗与退出行为说明、文件位置 |
| 运行日志 | 完整过程记录，可一键复制或在访达中显示 |

除此之外：

- 使用 macOS 钥匙串保存 VPN 口令
- 菜单栏图标可快速连接、断开、查看状态，并直达各设置分区
- 主菜单「连接」提供 ⌘K 连接、⇧⌘K 断开、⌘, 打开连接设置、⌘L 查看日志
- 后端退出时，日志会被翻译成一句可执行的提示（例如账户被拒、地址解析不了、UDP 1701 被拦），原始记录仍保留在运行日志里

构建完整的 `.app`：

```bash
./scripts/build-macos-app.sh
```

产物位于 `dist/BareL2TP.app`。首次打开后，在「连接设置」里填写服务器、账户和口令，再到「内网网段」填写要走 VPN 的网段。连接时 macOS 会弹出一次管理员授权窗口；授权用于创建 utun 接口和增删路由。口令不会出现在命令行或环境变量中，而是通过仅当前用户可访问的本地管道交给后端。

后端就是同一个命令行程序，以 `--daemon` 启动：授权窗口通过后命令会等到隧道真正建立才返回，界面因此能立刻知道这次连接成没成，而不必靠轮询日志去猜；等待期间日志会实时刷出来。守护化、PID 文件互斥、日志权限都由后端自己负责，`--runtime-uid` 让日志回到当前用户名下；PID 文件仍由后端所有，但以只读权限供界面判断状态，避免普通用户改写仍在运行的 root 进程记录。后端上次要是被强杀，留下的路由会在下一次连接前按记录自动回滚。运行期文件都在 `~/Library/Application Support/BareL2TP/`。

菜单栏图标开着时，⌘Q 只把窗口收起到菜单栏，VPN 继续连着；要真正退出，用菜单栏图标里的「退出 BareL2TP」。无论从哪里退出，应用都会先断开隧道并还原路由表。

应用跟随 macOS 的语言设置显示简体中文或英文，也可以在应用的「通用 → 语言」里单独切换（切换后需重新启动应用），或在「系统设置 → 通用 → 语言与地区 → 应用」里指定，两处改的是同一个设置。命令行后端的输出和「运行日志」固定为英文。

界面文案以英文原文作为本地化键，中文译文在 `app/Resources/zh-Hans.lproj/Localizable.strings`，英文的单复数规则在 `app/Resources/en.lproj/Localizable.stringsdict`。改了界面文案之后，运行下面的脚本检查中文译文是否有遗漏或过期：

```bash
python3 scripts/check-i18n.py
```

Swift 侧单元测试：

```bash
swift test --package-path app
```

## 配置说明

参见 [`config.example.toml`](config.example.toml)。口令优先从 `password` 或 `password_env` 获取；均不可用时交互输入。建议不要配置明文 `password`。`routes` 为必填项，只接受 IPv4 CIDR，没有内置默认值；写 `routes = []` 表示不添加任何网段路由。程序不会自动增加系统默认路由。

如果某个自定义网段也包含 L2TP 服务器地址，程序会在安装网段路由前查询原始网关，并添加更精确的 `/32` 主机路由，防止 UDP 外层流量被送回隧道。

连接前（包括 `--check`）会把 `routes` 与本机已启用网卡（回环和点对点隧道除外）的网段逐一比较：

| 情况 | 处理 |
| --- | --- |
| 与本地网段完全相同，比如内网和 WiFi 都是 `192.168.2.0/24` | 报错退出：系统已有直连路由，VPN 路由加不上 |
| 落在本地网段之内，且包含本地默认网关 | 报错退出：连上后所有上网流量都会进隧道 |
| 落在本地网段之内，不含网关 | 警告：本地同段的这些地址会进 VPN |
| 包含本地网段 | 警告：本地那一段仍走网卡，不进 VPN |

内网与所连 WiFi 同网段时，要么把 WiFi 换到不冲突的网段，要么只把需要访问的内网主机写成 `/32`（避开本地网关）。检测只看连接那一刻的网络，连接期间切换 WiFi 不会重新检查。

## 测试

不需要 root 的协议编解码和路由解析测试：

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

仓库的持续集成会在 macOS ARM64、macOS X64、Linux X64 和 Linux ARM64 上同时执行格式、测试、编译和 Clippy 检查。

## 持续集成与发版

GitHub Actions 会在 `main` 分支推送和拉取请求上执行以下检查：

- macOS ARM64、macOS X64、Linux X64、Linux ARM64 上的 Rust 格式、单元测试、编译和 Clippy 检查
- Linux X64 上额外检查 musl 目标能否编译
- macOS ARM64 和 macOS X64 上的 Swift 单元测试与完整 `.app` 构建

推送与 `Cargo.toml` 版本一致的 `v*` 标签后，发版工作流会重新运行测试，构建 Linux X64、Linux ARM64（每种架构各出 glibc 和 musl 静态链接两个版本）、macOS ARM64 和 macOS X64 命令行程序，构建两个架构临时签名的 macOS `.app`，然后创建 GitHub Release 并附上全部压缩包。

产物文件名带版本号，`-musl` 后缀的是静态链接版本，适合 glibc 太旧或者没有 glibc 的机器：

```text
barel2tp-1.0.0-linux-X64.tar.gz
barel2tp-1.0.0-linux-X64-musl.tar.gz
barel2tp-1.0.0-macos-ARM64.tar.gz
barel2tp-1.0.0-macos-app-ARM64.zip
```

例如当前版本的发版命令是：

```bash
git tag -a v1.0.0 -m "发布 v1.0.0"
git push origin v1.0.0
```

macOS 应用目前只使用临时签名，尚未使用 Apple Developer ID 签名和公证，因此从其他电脑首次打开时可能需要在系统设置中手动允许。

真实连接仍需在目标 L2TP 服务端上验证，因为不同厂商可能使用未纳入本实现的 PPP/L2TP 扩展。协议依据：[RFC 2661（L2TPv2）](https://datatracker.ietf.org/doc/html/rfc2661)、[RFC 1661（PPP）](https://datatracker.ietf.org/doc/html/rfc1661)、[RFC 1994（CHAP）](https://datatracker.ietf.org/doc/html/rfc1994)、[RFC 1332（IPCP）](https://datatracker.ietf.org/doc/html/rfc1332)。

## 许可证

本项目以 [MIT 许可证](LICENSE) 发布。
