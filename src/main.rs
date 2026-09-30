use std::{
    io::BufReader,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use barel2tp::{
    config::Config,
    control::ControlSocket,
    daemon::{self, Daemon, PidFile},
    l2tp::L2tpClient,
    overlap,
    password::{prompt_password, read_password_line},
    ppp::{self, PppRuntime, RuntimeEvent},
    route::RouteManager,
    tun::{TunDevice, configure_interface, ensure_privileges},
};
use clap::{ArgAction, Parser};
use tokio::{
    net::lookup_host,
    time::{Instant, MissedTickBehavior, interval_at},
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Parser)]
#[command(version, about = "Bare L2TP + PPP/CHAP-MD5 user-space VPN client")]
struct Cli {
    /// TOML configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Only validate the configuration; do not connect or change the network
    #[arg(long)]
    check: bool,

    /// More detailed protocol logs; may be repeated
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,

    /// Read one password line from standard input (used by the GUI through a pipe)
    #[arg(long)]
    password_stdin: bool,

    /// Create a local Unix datagram socket that accepts a disconnect command (Unix only)
    #[arg(long, requires = "control_uid")]
    control_socket: Option<PathBuf>,

    /// UID that owns the control socket
    #[arg(long, requires = "control_socket")]
    control_uid: Option<u32>,

    /// Move to the background and detach once the tunnel is up; stop with SIGTERM or the control socket (Unix only)
    #[arg(long)]
    daemon: bool,

    /// Append logs to this file; recommended together with --daemon (Unix only)
    #[arg(long)]
    log_file: Option<PathBuf>,

    /// PID file that records the process ID and prevents duplicate instances (Unix only)
    #[arg(long)]
    pid_file: Option<PathBuf>,

    /// State file recording installed routes, used by --cleanup after an abnormal exit (Unix only)
    #[arg(long)]
    state_file: Option<PathBuf>,

    /// Hand the log file to this UID; the PID file stays backend-owned and world-readable (Unix only)
    #[arg(long)]
    runtime_uid: Option<u32>,

    /// Show the status of the background process (Unix only)
    #[arg(long, conflicts_with_all = ["daemon", "check", "stop", "cleanup", "password_stdin"])]
    status: bool,

    /// Stop the background process and wait until its routes are cleaned up (Unix only)
    #[arg(long, conflicts_with_all = ["daemon", "check", "status", "cleanup", "password_stdin"])]
    stop: bool,

    /// Clean up routes and stale files left by an abnormal exit (kill -9, crash, power loss) (Unix only)
    #[arg(long, conflicts_with_all = ["daemon", "check", "status", "stop", "password_stdin"])]
    cleanup: bool,
}

/// Locations of the files used in background mode; unless given explicitly they live next to the
/// executable.
struct RuntimePaths {
    log: Option<PathBuf>,
    pid: Option<PathBuf>,
    state: Option<PathBuf>,
}

impl RuntimePaths {
    fn resolve(cli: &Cli) -> Result<Self> {
        // Foreground runs stay unchanged: logs go to the terminal and no PID file is written, so
        // the GUI is unaffected.
        let directory = if cli.daemon || cli.status || cli.stop || cli.cleanup {
            Some(daemon::default_runtime_dir()?)
        } else {
            None
        };
        Ok(Self {
            log: Self::pick(
                cli.log_file.as_deref(),
                directory.as_deref(),
                daemon::DEFAULT_LOG_NAME,
            )?,
            pid: Self::pick(
                cli.pid_file.as_deref(),
                directory.as_deref(),
                daemon::DEFAULT_PID_NAME,
            )?,
            state: Self::pick(
                cli.state_file.as_deref(),
                directory.as_deref(),
                daemon::DEFAULT_STATE_NAME,
            )?,
        })
    }

    fn pick(
        explicit: Option<&Path>,
        directory: Option<&Path>,
        name: &str,
    ) -> Result<Option<PathBuf>> {
        match explicit {
            // Daemonizing changes the working directory to `/`, so relative paths must be made
            // absolute first.
            Some(path) => absolute_path(path).map(Some),
            None => Ok(directory.map(|directory| directory.join(name))),
        }
    }
}

fn main() -> Result<()> {
    restore_sigpipe();
    let cli = Cli::parse();
    let paths = RuntimePaths::resolve(&cli)?;

    // Status and stop never touch the configuration, so they cannot fail because of a missing
    // config or password.
    if cli.status {
        return print_status(&paths);
    }
    if cli.stop {
        return stop_daemon(&paths);
    }
    if cli.cleanup {
        return clean_leftovers(&paths);
    }

    let mut config = Config::load(&cli.config)?;
    // Reject subnets that conflict with the local network before asking for the password or
    // building the tunnel, so the error reaches the terminal or GUI directly.
    let overlap_warnings = overlap::check(&config.routes)?;
    if cli.check {
        for warning in &overlap_warnings {
            eprintln!("warning: {warning}");
        }
        println!(
            "configuration OK: {} custom IPv4 routes",
            config.routes.len()
        );
        return Ok(());
    }

    // The password prompt and daemonizing both happen before the tunnel is built, so missing
    // privileges are caught here first.
    ensure_privileges()?;

    let control_socket = cli
        .control_socket
        .as_deref()
        .map(absolute_path)
        .transpose()?;

    // Daemonizing points stdin at /dev/null, so both interactive input and --password-stdin must be
    // read before forking.
    let mut password = read_password(&mut config, cli.password_stdin)?;

    let log = paths
        .log
        .as_deref()
        .map(daemon::open_log_file)
        .transpose()?;
    // Change the owner through the already-open descriptor so the path cannot be swapped during
    // authorization.
    if let (Some(log), Some(uid)) = (log.as_ref(), cli.runtime_uid) {
        log.chown_to(uid)?;
    }
    let daemon = if cli.daemon {
        // fork copies the plaintext password into the foreground and intermediate processes. Both
        // end through _exit without running destructors, so Zeroizing cannot wipe those copies and
        // they must be wiped by hand before exiting.
        Some(daemon::daemonize(log, || password.zeroize())?)
    } else {
        if let Some(log) = log {
            daemon::redirect_output(log)?;
        }
        None
    };

    // Disable colors when logging to a file so terminal escape sequences don't end up in the log.
    init_logging(cli.verbose, paths.log.is_none())?;
    for warning in &overlap_warnings {
        warn!("{warning}");
    }
    // The process ID is only final after the second fork, so the PID file must be written here.
    let _pid_file = paths.pid.as_deref().map(PidFile::acquire).transpose()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create the async runtime")?;
    runtime.block_on(run(
        config,
        password,
        control_socket,
        cli.control_uid,
        paths.state,
        daemon,
    ))
}

/// Rust ignores SIGPIPE at startup, so println! into a closed pipe panics and a common `--status |
/// head` prints an alarming backtrace. Restore the default disposition so the process ends quietly
/// on the signal like other command-line tools. The data path is unaffected: UDP, TUN and Unix
/// datagrams never raise SIGPIPE, and the program writes to no stream sockets.
#[cfg(unix)]
fn restore_sigpipe() {
    // SAFETY: signal only changes this process's SIGPIPE disposition, and all arguments are libc
    // constants.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn restore_sigpipe() {}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    std::path::absolute(path).with_context(|| format!("failed to resolve path {}", path.display()))
}

/// Prints the daemon status; exits with code 1 when it is not running so scripts can check it.
#[cfg(unix)]
fn print_status(paths: &RuntimePaths) -> Result<()> {
    let pid_path = paths.pid.as_deref().context("missing PID file location")?;
    let running = daemon::read_running_pid(pid_path)?.filter(|pid| daemon::process_exists(*pid));

    match running {
        Some(pid) => println!("daemon: running (PID {pid})"),
        None => println!("daemon: not running"),
    }
    println!("PID file: {}", pid_path.display());
    if let Some(log_path) = paths.log.as_deref() {
        println!("log file: {}", log_path.display());
    }
    // A state file without a running process means the previous run did not finish cleaning up.
    if running.is_none()
        && let Some(state_path) = paths.state.as_deref()
        && state_path.exists()
    {
        println!(
            "leftover routes: {} still exists; clean it up with:",
            state_path.display()
        );
        println!("  {}", cleanup_command(paths));
    }
    if let Some(log_path) = paths.log.as_deref() {
        print_recent_log(log_path);
    }

    if running.is_none() {
        std::process::exit(1);
    }
    Ok(())
}

/// Builds a cleanup command that can be copied and run as is. The default locations follow the
/// executable, and the user may not be in that directory, so just saying "use --cleanup" is not
/// enough to copy.
#[cfg(unix)]
fn cleanup_command(paths: &RuntimePaths) -> String {
    let executable = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "barel2tp".to_owned());
    let mut command = format!("sudo {} --cleanup", shell_quote(&executable));
    if let Some(pid_path) = paths.pid.as_deref() {
        command.push_str(&format!(
            " --pid-file {}",
            shell_quote(&pid_path.display().to_string())
        ));
    }
    if let Some(state_path) = paths.state.as_deref() {
        command.push_str(&format!(
            " --state-file {}",
            shell_quote(&state_path.display().to_string())
        ));
    }
    command
}

#[cfg(unix)]
fn shell_quote(source: &str) -> String {
    format!("'{}'", source.replace('\'', r#"'"'"'"#))
}

/// Stops the daemon and waits until it has cleaned up its routes.
#[cfg(unix)]
fn stop_daemon(paths: &RuntimePaths) -> Result<()> {
    let pid_path = paths.pid.as_deref().context("missing PID file location")?;
    let Some(pid) = daemon::read_running_pid(pid_path)?.filter(|pid| daemon::process_exists(*pid))
    else {
        println!("daemon is not running: {}", pid_path.display());
        std::process::exit(1);
    };

    daemon::request_stop(pid)?;
    if daemon::wait_until_stopped(pid_path, pid, std::time::Duration::from_secs(15))? {
        println!("daemon stopped (PID {pid}); routes cleaned up");
        return Ok(());
    }
    bail!(
        "daemon {pid} did not exit within 15 seconds; kill -9 {pid} forces it to stop but will not clean up routes"
    )
}

/// Shows the last few log lines, enough to tell whether the tunnel just became ready or is
/// retrying.
#[cfg(unix)]
fn print_recent_log(path: &Path) {
    match tail_lines(path, 3) {
        Ok(lines) if lines.is_empty() => {}
        Ok(lines) => {
            println!("recent log:");
            for line in lines {
                println!("  {line}");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            println!("recent log: permission denied; the daemon usually runs as root, use sudo");
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => println!("recent log: read failed ({error})"),
    }
}

/// Reads only the end of the log so a large file from a long run is not loaded into memory.
#[cfg(unix)]
fn tail_lines(path: &Path, count: usize) -> std::io::Result<Vec<String>> {
    use std::io::{Read, Seek, SeekFrom};

    const WINDOW: u64 = 8192;

    let Some(mut file) = barel2tp::secure_file::open_read_optional(path)? else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "log file does not exist",
        ));
    };
    let length = file.metadata()?.len();
    file.seek(SeekFrom::Start(length.saturating_sub(WINDOW)))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let text = String::from_utf8_lossy(&buffer);
    let mut lines: Vec<String> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .rev()
        .take(count)
        .map(str::to_owned)
        .collect();
    lines.reverse();
    Ok(lines)
}

/// Cleans up routes and stale files left behind by an abnormal exit.
#[cfg(unix)]
fn clean_leftovers(paths: &RuntimePaths) -> Result<()> {
    // Report the more specific "still running" case first; it can be checked without any
    // privileges.
    let pid_path = paths.pid.as_deref().context("missing PID file location")?;
    if let Some(pid) =
        daemon::read_running_pid(pid_path)?.filter(|pid| daemon::process_exists(*pid))
    {
        bail!(
            "daemon is still running (PID {pid}); stop it with --stop first, it cleans up its own routes"
        );
    }
    // Removing routes requires root. Stop early so a cleanup that fails entirely does not also
    // delete the leftover records.
    if !daemon::is_root() {
        bail!("cleaning up leftover routes requires administrator privileges; run again with sudo");
    }

    let state_path = paths
        .state
        .as_deref()
        .context("missing route state file location")?;
    let mut failed = 0;
    match barel2tp::route::cleanup_leftovers(state_path)? {
        None => println!("no leftover routes to clean up: {}", state_path.display()),
        Some(report) if report.rebooted => {
            println!(
                "the records are from a previous boot; the routes disappeared with the reboot, nothing to clean up"
            );
        }
        Some(report)
            if report.removed.is_empty()
                && report.absent.is_empty()
                && report.failed.is_empty() =>
        {
            println!("the previous run installed no routes");
        }
        Some(report) => {
            for route in &report.removed {
                println!("removed leftover route {route}");
            }
            for route in &report.absent {
                println!("no need to remove {route}: it is no longer in the routing table");
            }
            for (route, reason) in &report.failed {
                println!("failed to remove {route}: {reason}");
            }
            failed = report.failed.len();
            if failed > 0 {
                println!(
                    "the {failed} failed records were kept in {}; fix the cause and run --cleanup again, \
                         or check with netstat -rn",
                    state_path.display()
                );
            }
        }
    }

    // Only remove the PID file when it is a stale leftover; keeping it is pointless when routes
    // were not fully cleaned, but that must not abort the cleanup.
    if pid_path.exists() {
        barel2tp::secure_file::remove(pid_path)
            .with_context(|| format!("failed to remove stale PID file {}", pid_path.display()))?;
        println!("removed stale PID file {}", pid_path.display());
    }
    if failed > 0 {
        bail!("{failed} leftover routes could not be removed");
    }
    Ok(())
}

#[cfg(not(unix))]
fn clean_leftovers(_paths: &RuntimePaths) -> Result<()> {
    bail!("--cleanup is only supported on macOS and Linux")
}

#[cfg(not(unix))]
fn print_status(_paths: &RuntimePaths) -> Result<()> {
    bail!("--status is only supported on macOS and Linux")
}

#[cfg(not(unix))]
fn stop_daemon(_paths: &RuntimePaths) -> Result<()> {
    bail!("--stop is only supported on macOS and Linux")
}

fn read_password(config: &mut Config, password_stdin: bool) -> Result<Zeroizing<String>> {
    if password_stdin {
        return read_password_line(BufReader::new(std::io::stdin().lock()));
    }
    match config.take_password()? {
        Some(password) => Ok(password),
        None => prompt_password("VPN password: "),
    }
}

async fn run(
    config: Config,
    password: Zeroizing<String>,
    control_socket: Option<PathBuf>,
    control_uid: Option<u32>,
    state_path: Option<PathBuf>,
    mut daemon: Option<Daemon>,
) -> Result<()> {
    // Creating the TUN is the only privileged step in the whole chain. Doing it before dialing and
    // authenticating reports missing privileges immediately, instead of after the tunnel is up and
    // the password verified.
    let tun = TunDevice::create()?;
    let control = control_socket
        .as_deref()
        .map(|path| ControlSocket::bind(path, control_uid))
        .transpose()?;
    let peer = resolve_server(&config.server, config.port).await?;
    let hostname = config.client_hostname();

    let mut client = L2tpClient::connect(peer, config.local_bind, config.local_port).await?;
    let connection = async {
        client
            .establish(&hostname, config.timeout(), config.retries)
            .await?;

        let ppp_timeout = config.timeout();
        let ppp_retries = config.retries;
        let hello_interval = config.hello_interval();
        let (network, mut runtime) = ppp::negotiate(
            &mut client,
            config.username,
            password,
            config.mtu,
            config.request_dns,
            ppp_timeout,
            ppp_retries,
        )
        .await?;

        configure_interface(&tun, &network, config.mtu).with_context(|| {
            format!("failed to configure interface {}; macOS usually needs sudo, Linux needs CAP_NET_ADMIN", tun.name())
        })?;

        let mut routes = RouteManager::new(tun.name()).with_state_file(state_path);
        routes
            .install(*client.peer().ip(), &config.routes)
            .context("failed to install VPN routes")?;
        if config.routes.is_empty() {
            warn!("routes is empty; the tunnel is up but no subnet will be routed into the TUN");
        }

        info!(
            interface = tun.name(),
            local_address = %network.local_address,
            peer_address = ?network.peer_address,
            routes = config.routes.len(),
            "VPN ready");
        // Let the foreground process exit only once the tunnel is really usable, so a failed
        // background start never reports success.
        if let Some(daemon) = daemon.as_mut() {
            daemon.notify_ready();
        }

        let forwarding_result = forward(
            &mut client,
            &mut runtime,
            &tun,
            config.mtu,
            ppp_timeout,
            ppp_retries,
            hello_interval,
        )
        .await;
        routes.cleanup();
        forwarding_result
    };

    let result = tokio::select! {
        result = connection => result,
        signal = wait_for_termination() => {
            let signal = signal?;
            info!(signal, "received termination signal; cleaning up routes and disconnecting");
            Ok(())
        }
        signal = wait_for_disconnect(control.as_ref()) => {
            signal?;
            info!("received disconnect request from the GUI; cleaning up routes and disconnecting");
            Ok(())
        }
    };

    client.shutdown().await;
    result
}

/// Waits for any termination signal. In background mode the process is stopped with SIGTERM, which
/// must be caught here; otherwise the default action kills the process and leaves its routes behind
/// with nobody to clean them up.
#[cfg(unix)]
async fn wait_for_termination() -> Result<&'static str> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate()).context("failed to listen for SIGTERM")?;
    let mut hangup = signal(SignalKind::hangup()).context("failed to listen for SIGHUP")?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.context("failed to listen for Ctrl-C")?;
            Ok("Ctrl-C")
        }
        _ = terminate.recv() => Ok("SIGTERM"),
        _ = hangup.recv() => Ok("SIGHUP"),
    }
}

#[cfg(not(unix))]
async fn wait_for_termination() -> Result<&'static str> {
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for Ctrl-C")?;
    Ok("Ctrl-C")
}

async fn wait_for_disconnect(control: Option<&ControlSocket>) -> Result<()> {
    match control {
        Some(control) => control.wait_for_disconnect().await,
        None => std::future::pending().await,
    }
}

async fn forward(
    client: &mut L2tpClient,
    runtime: &mut PppRuntime,
    tun: &TunDevice,
    mtu: u16,
    control_timeout: std::time::Duration,
    control_retries: u32,
    hello_interval: std::time::Duration,
) -> Result<()> {
    let mut tun_buffer = vec![0u8; mtu as usize + 64];
    let mut keepalive = interval_at(Instant::now() + hello_interval, hello_interval);
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            ppp_frame = client.recv_ppp() => {
                let ppp_frame = ppp_frame?;
                match runtime.handle_frame(client, &ppp_frame).await? {
                    RuntimeEvent::None => {}
                    RuntimeEvent::Ipv4(packet) => tun.write_packet(&packet).await?,
                    RuntimeEvent::NetworkConfig(network) => {
                        configure_interface(tun, &network, mtu)
                            .context("failed to update the TUN address after PPP renegotiation")?;
                        info!(
                            local_address = %network.local_address,
                            peer_address = ?network.peer_address,
                            "TUN address updated after PPP renegotiation");
                    }
                }
            }
            tun_packet = tun.read_packet(&mut tun_buffer) => {
                let length = tun_packet?;
                runtime.send_ipv4(client, &tun_buffer[..length]).await?;
            }
            _ = keepalive.tick() => {
                client.send_hello(control_timeout, control_retries).await?;
            }
        }
    }
}

async fn resolve_server(host: &str, port: u16) -> Result<std::net::SocketAddrV4> {
    let addresses = lookup_host((host, port))
        .await
        .with_context(|| format!("failed to resolve L2TP server {host}"))?;
    for address in addresses {
        if let SocketAddr::V4(address) = address {
            return Ok(address);
        }
    }
    bail!("L2TP server {host} has no IPv4 address; only IPv4 outer transport is supported")
}

fn init_logging(verbosity: u8, ansi: bool) -> Result<()> {
    let default_level = match verbosity {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default_level))
        .context("invalid log filter")?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(ansi)
        .compact()
        .try_init()
        .map_err(|error| anyhow!("failed to initialize logging: {error}"))?;
    Ok(())
}
