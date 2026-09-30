# barel2tp

English | [简体中文](README.zh-CN.md)

A bare L2TPv2 client for macOS and Linux, written in Rust. It does not use the system VPN framework, and it does not spawn `pppd` or `xl2tpd`. The program implements L2TPv2, PPP LCP, CHAP-MD5, IPCP and IP forwarding entirely in user space.

Only the IPv4 subnets listed in the configuration are routed to the TUN interface it creates. That makes it a good fit when you only need to reach a few remote internal subnets and cannot (or would rather not) set up a system VPN profile.

## Security boundary

Bare L2TP provides no encryption, no integrity protection, and no reliable peer authentication. CHAP-MD5 only authenticates the PPP user. It does not encrypt session traffic and does not protect L2TP packets. Use this only on trusted networks, over an existing secure transport, or where you have explicitly accepted that risk.

PAP, MS-CHAP and non-MD5 CHAP algorithms are rejected, so authentication cannot be silently downgraded.

## Features

- L2TPv2 tunnel and session setup (SCCRQ/SCCRP/SCCCN, ICRQ/ICRP/ICCN)
- Control-message sequencing, ZLB acks, duplicate handling and exponential-backoff retransmission
- Active L2TP HELLO keepalive, failure detection and control-packet source validation
- Data channel with or without sequence numbers
- Bidirectional PPP LCP negotiation, runtime LCP/IPCP renegotiation and Echo replies
- RFC 1994 CHAP-MD5, including re-authentication during the session
- IPCP IPv4 address negotiation, with optional primary and secondary DNS requests
- macOS `utun` and Linux `/dev/net/tun`
- Custom IPv4 subnet routes. If a routed subnet contains the VPN server, the outer server route is pinned automatically
- Route cleanup on Ctrl-C, SIGTERM/SIGHUP and error exit
- Optional background mode: `--daemon`, `--status`, `--stop` and `--cleanup` (macOS/Linux)

Current limitations: IPv4 only, a single tunnel and a single PPP session. There is no L2TP tunnel shared secret, IPv6, IPsec, MPPE, compression or multilink PPP, and system DNS is never modified.

## Build

You need a recent stable Rust (1.85+):

```bash
cargo build --release
```

| OS | TUN backend | Privileges | Extra requirements |
| --- | --- | --- | --- |
| macOS | kernel `utun` | `sudo` | none |
| Linux | `/dev/net/tun` | `root` or `CAP_NET_ADMIN` | `iproute2` |

Copy the example config and edit it:

```bash
cp config.example.toml config.local.toml
export BAREL2TP_PASSWORD='your password'
```

If the environment variable is not set, the password is read from the controlling terminal without echo. This also works under `sudo`, and the password never appears in command-line arguments.

Validate the configuration without side effects:

```bash
./target/release/barel2tp --config config.local.toml --check
```

## Run

On macOS, configuring the utun address and routes usually requires administrator privileges:

```bash
sudo --preserve-env=BAREL2TP_PASSWORD \
  ./target/release/barel2tp --config config.local.toml
```

On Linux you can run as root, or grant `CAP_NET_ADMIN` and make sure the user can open `/dev/net/tun`:

```bash
sudo setcap cap_net_admin+ep ./target/release/barel2tp
./target/release/barel2tp --config config.local.toml
```

Use `-v` for negotiation status and `-vv` for per-frame logs. `RUST_LOG` overrides the log level.

### Background mode

`--daemon` detaches from the terminal once the tunnel is up (macOS and Linux only):

```bash
sudo ./target/release/barel2tp --config config.local.toml --daemon
```

The foreground command returns 0 only after the tunnel is actually established. On failure it returns 1 and points you to the log file.

By default, the log and PID files live **next to the executable** (for example `target/release/barel2tp.log`). The home directory is not used because under `sudo` it becomes `/var/root`. Use `--log-file` and `--pid-file` to change these locations.

```bash
./target/release/barel2tp --status
sudo ./target/release/barel2tp --stop
```

`--status` prints the process state, file locations and the last three log lines. It exits with 1 when the process is not running. `--stop` sends SIGTERM and waits up to 15 seconds for a clean exit, so routes are already cleaned up when it returns. Neither command reads the config file or needs the password.

### Cleanup after abnormal exit

After `kill -9`, a crash or a power loss, the routes cannot be rolled back. In background mode every installed route is recorded in a state file (`barel2tp.state` by default), so you can undo them precisely:

```bash
sudo ./target/release/barel2tp --cleanup
```

Cleanup first verifies that no daemon is running. Entries that fail to delete stay in the state file for a retry. Records from before a reboot are discarded, because `utun` names may already have been reused. Foreground runs do not write a state file unless you pass `--state-file`.

## macOS app

The repository also contains a native SwiftUI menu-bar app for macOS 13+. It stores the password in the macOS Keychain and hands it to the backend through a private local pipe, never through the command line or environment variables.

```bash
./scripts/build-macos-app.sh
```

This produces `dist/BareL2TP.app`. On first launch, enter the server, account and password under Connection, then add the subnets to route. macOS asks for administrator authorization once per connection, to create the utun interface and modify routes. Runtime files live in `~/Library/Application Support/BareL2TP/`.

The app follows the macOS language setting and is available in English and Simplified Chinese. You can also choose a language for it alone under General → Language in the app (it asks to relaunch), or under System Settings → General → Language & Region → Applications; both change the same setting. The command-line backend and the log are always in English.

UI strings use the English source text as localization keys. The Chinese translation lives in `app/Resources/zh-Hans.lproj/Localizable.strings`, and English plural rules in `app/Resources/en.lproj/Localizable.stringsdict`. After changing UI text, check that the Chinese translation is complete and up to date:

```bash
python3 scripts/check-i18n.py
```

Swift unit tests:

```bash
swift test --package-path app
```

## Configuration

See [`config.example.toml`](config.example.toml). The password comes from `password` or `password_env`, and is prompted for interactively when neither is available. Plain-text `password` is discouraged. `routes` is **required** and accepts IPv4 CIDRs only. `routes = []` means no subnet routes are added. The default route is never changed.

Before connecting (and during `--check`), each entry in `routes` is compared with the subnets of the active local interfaces (loopback and point-to-point tunnels excluded):

| Situation | Result |
| --- | --- |
| Identical to a local subnet | Error: a directly connected route already exists |
| Inside a local subnet and contains the local default gateway | Error: all traffic would be sent into the tunnel |
| Inside a local subnet, gateway not included | Warning |
| Contains a local subnet | Warning: the local part still uses the local interface |

## Testing

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

CI runs formatting, tests, builds and Clippy on macOS ARM64/X64 and Linux X64/ARM64, checks the musl target, and builds the macOS app on both architectures. Pushing a `v*` tag that matches the version in `Cargo.toml` builds release archives (including static musl builds for Linux) and publishes a GitHub Release.

The macOS app is currently ad-hoc signed and not notarized, so on other machines you may need to allow it manually in System Settings on first launch.

Real-world connections still need to be verified against your L2TP server, because vendors may use PPP/L2TP extensions this implementation does not support. References: [RFC 2661 (L2TPv2)](https://datatracker.ietf.org/doc/html/rfc2661), [RFC 1661 (PPP)](https://datatracker.ietf.org/doc/html/rfc1661), [RFC 1994 (CHAP)](https://datatracker.ietf.org/doc/html/rfc1994), [RFC 1332 (IPCP)](https://datatracker.ietf.org/doc/html/rfc1332).

## License

[MIT](LICENSE)
