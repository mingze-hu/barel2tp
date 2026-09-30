use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::{overlap::DefaultGateway, secure_file};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ServerPath {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway: Option<Ipv4Addr>,
    interface: String,
}

/// Snapshot of the installed routes. When the process is killed, crashes or loses power there is no
/// time to roll back; the next `--cleanup` reads this record and removes exactly the routes that
/// were added.
#[derive(Debug, Default, Serialize, Deserialize)]
struct RouteState {
    /// System boot identifier at the time the record was written. After a reboot the routing table
    /// is empty anyway, and `utun` names get reused by other tunnels, so deleting from an old
    /// record would only hit someone else's routes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    boot: Option<String>,
    /// One section per run. Records not rolled back after an abnormal exit are carried over by the
    /// next run instead of being overwritten by the new session.
    #[serde(default)]
    sessions: Vec<RouteSession>,
}

/// Routes installed by one run.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct RouteSession {
    interface: String,
    #[serde(default)]
    routes: Vec<Ipv4Net>,
    // TOML requires table fields to come after plain fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pinned_server: Option<PinnedServer>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PinnedServer {
    address: Ipv4Addr,
    path: ServerPath,
}

impl RouteSession {
    fn is_empty(&self) -> bool {
        self.routes.is_empty() && self.pinned_server.is_none()
    }
}

impl RouteState {
    fn save(&self, path: &Path) -> Result<()> {
        let source = toml::to_string(self).context("failed to serialize route state")?;
        secure_file::atomic_write(path, source.as_bytes(), 0o600)
            .with_context(|| format!("failed to write route state file {}", path.display()))
    }

    /// Reads the routes recorded by the previous run; a missing file means the previous run exited
    /// normally.
    fn load(path: &Path) -> Result<Option<Self>> {
        let source = match secure_file::read_to_string_optional(path) {
            Ok(Some(source)) => source,
            Ok(None) => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to read route state file {}", path.display())
                });
            }
        };
        let state: Self = toml::from_str(&source)
            .with_context(|| format!("invalid route state file {}", path.display()))?;
        Ok(Some(state))
    }

    /// Whether the record comes from a previous boot. It counts only when both boot identifiers can
    /// be read and differ; if either is unavailable, assume the same boot and err on the side of
    /// trying to delete.
    fn rebooted(&self) -> bool {
        match (self.boot.as_deref(), boot_id()) {
            (Some(recorded), Some(current)) => recorded != current,
            _ => false,
        }
    }

    fn sessions_to_roll_back(&self) -> impl Iterator<Item = &RouteSession> {
        self.sessions.iter().filter(|session| !session.is_empty())
    }
}

/// System boot identifier, used to tell whether a record was written during this boot.
#[cfg(target_os = "linux")]
fn boot_id() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|value| value.trim().to_owned())
}

/// System boot identifier, used to tell whether a record was written during this boot.
#[cfg(target_os = "macos")]
fn boot_id() -> Option<String> {
    let mut boot_time: libc::timeval = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<libc::timeval>();
    // SAFETY: kern.boottime returns a timeval, the buffer size matches it, and the other arguments
    // are null as documented.
    let status = unsafe {
        libc::sysctlbyname(
            c"kern.boottime".as_ptr(),
            (&raw mut boot_time).cast(),
            &raw mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    (status == 0).then(|| format!("{}.{}", boot_time.tv_sec, boot_time.tv_usec))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn boot_id() -> Option<String> {
    None
}

/// Result of `--cleanup`.
#[derive(Debug, Default)]
pub struct CleanupReport {
    /// Actually removed from the routing table.
    pub removed: Vec<String>,
    /// Recorded but already gone from the system, most likely removed by the kernel along with the
    /// TUN interface. This is normal.
    pub absent: Vec<String>,
    /// Failed to remove. These records stay in the state file so they can be retried later.
    pub failed: Vec<(String, String)>,
    /// The records come from a previous boot; the routes disappeared with the reboot and need not,
    /// and must not, be deleted.
    pub rebooted: bool,
}

/// Rolls back the routes recorded in the state file.
///
/// When the TUN interface disappears the kernel usually removes the subnet routes pointing at it,
/// so "already gone" is the common case and goes into `absent`. What really needs rolling back is
/// the pinned server route via the physical gateway, which does not disappear with the interface.
/// Only entries that genuinely fail to delete stay in the state file for the next retry.
pub fn cleanup_leftovers(path: &Path) -> Result<Option<CleanupReport>> {
    let Some(state) = RouteState::load(path)? else {
        return Ok(None);
    };

    // After a reboot the records must not be used for deletion: the utun name probably belongs to
    // another tunnel by now.
    if state.rebooted() {
        secure_file::remove(path)
            .with_context(|| format!("failed to remove route state file {}", path.display()))?;
        return Ok(Some(CleanupReport {
            rebooted: true,
            ..CleanupReport::default()
        }));
    }

    let mut report = CleanupReport::default();
    let remaining: Vec<RouteSession> = state
        .sessions_to_roll_back()
        .map(|session| roll_back(session, &mut report))
        .filter(|session| !session.is_empty())
        .collect();

    if remaining.is_empty() {
        // Once everything is handled the file is no longer kept; otherwise every --cleanup would
        // report the same leftovers again.
        secure_file::remove(path)
            .with_context(|| format!("failed to remove route state file {}", path.display()))?;
    } else {
        // Entries that could not be deleted must be kept: dropping the record after one failure
        // would leave the leftover routes untraceable.
        RouteState {
            boot: state.boot.clone(),
            sessions: remaining,
        }
        .save(path)?;
    }
    Ok(Some(report))
}

/// Rolls back one run's records and returns the part that genuinely failed to delete and must be
/// kept.
fn roll_back(session: &RouteSession, report: &mut CleanupReport) -> RouteSession {
    let mut remaining = RouteSession {
        interface: session.interface.clone(),
        ..RouteSession::default()
    };

    for route in session.routes.iter().rev() {
        match delete_network_route_if_present(*route, &session.interface) {
            Ok(true) => report.removed.push(route.to_string()),
            Ok(false) => report.absent.push(route.to_string()),
            Err(error) => {
                report
                    .failed
                    .push((route.to_string(), format!("{error:#}")));
                remaining.routes.push(*route);
            }
        }
    }
    // The rollback above ran in reverse; restore installation order for what remains so the next
    // retry is again in reverse.
    remaining.routes.reverse();

    if let Some(pinned) = &session.pinned_server {
        let description = format!("{}/32 (VPN server pinned route)", pinned.address);
        match delete_server_pin_if_present(pinned.address, &pinned.path) {
            Ok(true) => report.removed.push(description),
            Ok(false) => report.absent.push(description),
            Err(error) => {
                report.failed.push((description, format!("{error:#}")));
                remaining.pinned_server = Some(pinned.clone());
            }
        }
    }
    remaining
}

pub struct RouteManager {
    interface: String,
    installed_routes: Vec<Ipv4Net>,
    pinned_server: Option<(Ipv4Addr, ServerPath)>,
    state_path: Option<PathBuf>,
    /// Records left by a previous abnormal exit that had not been rolled back when this run
    /// started. They are carried along unchanged so this run's records never overwrite them and
    /// make those leftover routes untraceable.
    carried: Vec<RouteSession>,
}

impl RouteManager {
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            installed_routes: Vec::new(),
            pinned_server: None,
            state_path: None,
            carried: Vec::new(),
        }
    }

    /// Sets the file that records installed routes; without it nothing is persisted and routes must
    /// be cleaned up by hand after an abnormal exit.
    ///
    /// Records already in the file are carried over: they are leftovers from a previous abnormal
    /// exit that nobody has rolled back, and overwriting them would erase them. Records from before
    /// a reboot are the exception, because the routing table is empty then.
    pub fn with_state_file(mut self, path: Option<PathBuf>) -> Self {
        self.carried = match path.as_deref().map(RouteState::load).transpose() {
            Ok(Some(Some(state))) if !state.rebooted() => {
                state.sessions_to_roll_back().cloned().collect()
            }
            Ok(_) => Vec::new(),
            // An unreadable file (most likely a truncated old one) should not block the connection,
            // but the user must know the records were lost.
            Err(error) => {
                warn!(%error, "cannot read the existing route state file; records from the previous abnormal exit cannot be carried over");
                Vec::new()
            }
        };
        self.state_path = path;
        self
    }

    pub fn install(&mut self, server: Ipv4Addr, routes: &[Ipv4Net]) -> Result<()> {
        if routes.iter().any(|network| network.contains(&server)) {
            let path = query_server_path(server)
                .context("failed to look up the original route to the VPN server")?;
            if path.interface == self.interface {
                bail!(
                    "the original route to the VPN server already points at the new TUN; cannot safely pin the server route"
                );
            }
            // Record before acting: if the process is killed between installing and persisting, the
            // route becomes a leftover with no record.
            // Recording one extra route that was never installed is harmless; --cleanup treats it
            // as "already gone".
            self.pinned_server = Some((server, path.clone()));
            self.persist();
            match add_server_pin(server, &path) {
                Ok(true) => {
                    debug!(%server, ?path, "pinned the outer route to the L2TP server")
                }
                // The route already existed and was not installed by this run. It must not be
                // recorded as ours, or exiting would delete someone else's route.
                Ok(false) => {
                    self.pinned_server = None;
                    self.persist();
                }
                Err(error) => {
                    self.pinned_server = None;
                    self.persist();
                    return Err(error);
                }
            }
        }

        for route in routes {
            // As above: record first, then add.
            self.installed_routes.push(*route);
            self.persist();
            if let Err(error) = add_network_route(*route, &self.interface) {
                self.cleanup();
                return Err(error).with_context(|| format!("failed to add route {route}"));
            }
            debug!(%route, interface = %self.interface, "added VPN subnet route");
        }
        Ok(())
    }

    pub fn cleanup(&mut self) {
        let mut remaining_routes = Vec::new();
        for route in self.installed_routes.drain(..).rev() {
            match delete_network_route_if_present(route, &self.interface) {
                Ok(_) => {}
                Err(error) => {
                    warn!(%route, %error, "failed to remove VPN subnet route; keeping the record for a later retry");
                    remaining_routes.push(route);
                }
            }
        }
        remaining_routes.reverse();
        self.installed_routes = remaining_routes;

        if let Some((server, path)) = self.pinned_server.take()
            && let Err(error) = delete_server_pin_if_present(server, &path)
        {
            warn!(%server, %error, "failed to remove the pinned L2TP server route; keeping the record for a later retry");
            self.pinned_server = Some((server, path));
        }
        if self.installed_routes.is_empty() && self.pinned_server.is_none() {
            self.discard_state();
        } else {
            self.persist();
        }
    }

    /// Writes the currently installed routes to the state file. Failures only warn: the tunnel is
    /// already up and should not be interrupted for an auxiliary file.
    fn persist(&self) {
        let Some(path) = self.state_path.as_deref() else {
            return;
        };
        if let Err(error) = self.state().save(path) {
            warn!(path = %path.display(), %error, "failed to record route state; routes must be cleaned up manually after an abnormal exit");
        }
    }

    /// Carried-over records plus this run's records.
    fn state(&self) -> RouteState {
        let current = RouteSession {
            interface: self.interface.clone(),
            routes: self.installed_routes.clone(),
            pinned_server: self
                .pinned_server
                .as_ref()
                .map(|(address, path)| PinnedServer {
                    address: *address,
                    path: path.clone(),
                }),
        };
        let mut sessions = self.carried.clone();
        if !current.is_empty() {
            sessions.push(current);
        }
        RouteState {
            boot: boot_id(),
            sessions,
        }
    }

    /// This run's routes are fully rolled back. Carried-over records are still unhandled and must
    /// be kept; the state file is only worthless once nothing is left.
    fn discard_state(&self) {
        let Some(path) = self.state_path.as_deref() else {
            return;
        };
        if !self.carried.is_empty() {
            self.persist();
            return;
        }
        if let Err(error) = secure_file::remove(path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %path.display(), %error, "failed to remove route state file");
        }
    }
}

impl Drop for RouteManager {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(target_os = "macos")]
fn query_server_path(server: Ipv4Addr) -> Result<ServerPath> {
    let output = command_output("route", &["-n", "get", &server.to_string()])?;
    parse_macos_route_get(&output)
}

#[cfg(target_os = "linux")]
fn query_server_path(server: Ipv4Addr) -> Result<ServerPath> {
    let output = command_output("ip", &["-4", "route", "get", &server.to_string()])?;
    parse_linux_route_get(&output)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn query_server_path(_server: Ipv4Addr) -> Result<ServerPath> {
    bail!("route management is not available on this platform")
}

/// Next hop of the system default route. Returns `None` when it cannot be found (offline, or the
/// default route goes through another tunnel).
pub(crate) fn default_gateway() -> Option<DefaultGateway> {
    let path = match query_default_path() {
        Ok(path) => path?,
        Err(error) => {
            debug!(%error, "failed to look up the default route");
            return None;
        }
    };
    Some(DefaultGateway {
        address: path.gateway?,
        interface: path.interface,
    })
}

#[cfg(target_os = "macos")]
fn query_default_path() -> Result<Option<ServerPath>> {
    match command_output("route", &["-n", "get", "default"]) {
        Ok(output) => parse_macos_route_get(&output).map(Some),
        // Without a default route, route fails with "not in table"; that is not an error.
        Err(error) if error.to_string().contains("not in table") => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn query_default_path() -> Result<Option<ServerPath>> {
    let output = command_output("ip", &["-4", "route", "show", "default"])?;
    output
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(parse_linux_route_get)
        .transpose()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn query_default_path() -> Result<Option<ServerPath>> {
    Ok(None)
}

#[cfg(target_os = "macos")]
fn add_server_pin(server: Ipv4Addr, path: &ServerPath) -> Result<bool> {
    let server = server.to_string();
    let result = if let Some(gateway) = path.gateway {
        command_status(
            "route",
            &["-n", "add", "-host", &server, &gateway.to_string()],
        )
    } else {
        command_status(
            "route",
            &["-n", "add", "-host", &server, "-interface", &path.interface],
        )
    };
    tolerate_existing(result)
}

#[cfg(target_os = "linux")]
fn add_server_pin(server: Ipv4Addr, path: &ServerPath) -> Result<bool> {
    let server = format!("{server}/32");
    let mut arguments = vec!["-4", "route", "add", &server];
    let gateway;
    if let Some(value) = path.gateway {
        gateway = value.to_string();
        arguments.extend(["via", &gateway]);
    }
    arguments.extend(["dev", &path.interface]);
    tolerate_existing(command_status("ip", &arguments))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn add_server_pin(_server: Ipv4Addr, _path: &ServerPath) -> Result<bool> {
    bail!("route management is not available on this platform")
}

#[cfg(target_os = "macos")]
fn delete_server_pin(server: Ipv4Addr, path: &ServerPath) -> Result<()> {
    let server = server.to_string();
    if let Some(gateway) = path.gateway {
        command_status(
            "route",
            &["-n", "delete", "-host", &server, &gateway.to_string()],
        )
    } else {
        command_status(
            "route",
            &[
                "-n",
                "delete",
                "-host",
                &server,
                "-interface",
                &path.interface,
            ],
        )
    }
}

#[cfg(target_os = "linux")]
fn delete_server_pin(server: Ipv4Addr, path: &ServerPath) -> Result<()> {
    let server = format!("{server}/32");
    let mut arguments = vec!["-4", "route", "del", &server];
    let gateway;
    if let Some(value) = path.gateway {
        gateway = value.to_string();
        arguments.extend(["via", &gateway]);
    }
    arguments.extend(["dev", &path.interface]);
    command_status("ip", &arguments)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn delete_server_pin(_server: Ipv4Addr, _path: &ServerPath) -> Result<()> {
    bail!("route management is not available on this platform")
}

#[cfg(target_os = "macos")]
fn add_network_route(network: Ipv4Net, interface: &str) -> Result<()> {
    command_status(
        "route",
        &[
            "-n",
            "add",
            "-net",
            &network.to_string(),
            "-interface",
            interface,
        ],
    )
}

#[cfg(target_os = "linux")]
fn add_network_route(network: Ipv4Net, interface: &str) -> Result<()> {
    command_status(
        "ip",
        &["-4", "route", "add", &network.to_string(), "dev", interface],
    )
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn add_network_route(_network: Ipv4Net, _interface: &str) -> Result<()> {
    bail!("route management is not available on this platform")
}

#[cfg(target_os = "macos")]
fn delete_network_route(network: Ipv4Net, interface: &str) -> Result<()> {
    command_status(
        "route",
        &[
            "-n",
            "delete",
            "-net",
            &network.to_string(),
            "-interface",
            interface,
        ],
    )
}

#[cfg(target_os = "linux")]
fn delete_network_route(network: Ipv4Net, interface: &str) -> Result<()> {
    command_status(
        "ip",
        &["-4", "route", "del", &network.to_string(), "dev", interface],
    )
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn delete_network_route(_network: Ipv4Net, _interface: &str) -> Result<()> {
    bail!("route management is not available on this platform")
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn command_output(program: &str, arguments: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .with_context(|| format!("failed to run {program}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let stderr = if stderr.is_empty() {
            "no error output".to_owned()
        } else {
            stderr
        };
        bail!(
            "command {program} {} failed ({}): {}",
            arguments.join(" "),
            output.status,
            stderr
        );
    }
    String::from_utf8(output.stdout).context("route command returned non-UTF-8 output")
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn command_status(program: &str, arguments: &[&str]) -> Result<()> {
    command_output(program, arguments).map(|_| ())
}

/// Deletes a subnet route and returns whether it actually existed.
fn delete_network_route_if_present(network: Ipv4Net, interface: &str) -> Result<bool> {
    tolerate_missing(delete_network_route(network, interface))
}

/// Deletes the pinned server route and returns whether it actually existed.
fn delete_server_pin_if_present(server: Ipv4Addr, path: &ServerPath) -> Result<bool> {
    tolerate_missing(delete_server_pin(server, path))
}

/// Tells "the route is already gone" apart from "the route cannot be deleted". The former is normal
/// after the tunnel goes down; the latter must reach the caller, or unfinished cleanup would be
/// treated as done.
fn tolerate_missing(result: Result<()>) -> Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(error) => {
            let message = error.to_string().to_ascii_lowercase();
            // macOS: "not in table"; Linux: "No such process".
            let missing = ["not in table", "no such process"]
                .iter()
                .any(|hint| message.contains(hint));
            if missing { Ok(false) } else { Err(error) }
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn tolerate_existing(result: Result<()>) -> Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(error) => {
            let message = error.to_string().to_ascii_lowercase();
            if message.contains("file exists") || message.contains("already exists") {
                debug!("server host route already exists; keeping it");
                Ok(false)
            } else {
                Err(error)
            }
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_route_get(output: &str) -> Result<ServerPath> {
    let mut gateway = None;
    let mut interface = None;
    for line in output.lines() {
        let Some((key, value)) = line.trim().split_once(':') else {
            continue;
        };
        match key.trim() {
            "gateway" => gateway = value.trim().parse().ok(),
            "interface" => interface = Some(value.trim().to_owned()),
            _ => {}
        }
    }
    let interface = interface.context("no interface in route -n get output")?;
    Ok(ServerPath { gateway, interface })
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_route_get(output: &str) -> Result<ServerPath> {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    let interface = value_after(&tokens, "dev")
        .context("no dev in ip route get output")?
        .to_owned();
    let gateway = value_after(&tokens, "via").and_then(|value| value.parse().ok());
    Ok(ServerPath { gateway, interface })
}

#[cfg(any(target_os = "linux", test))]
fn value_after<'a>(tokens: &'a [&str], key: &str) -> Option<&'a str> {
    tokens
        .windows(2)
        .find(|window| window[0] == key)
        .map(|window| window[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testing::temp_path;
    use std::fs;

    fn sample_session() -> RouteSession {
        RouteSession {
            interface: "utun4".to_owned(),
            routes: vec![
                "192.168.2.0/24".parse().unwrap(),
                "192.168.30.0/24".parse().unwrap(),
            ],
            pinned_server: Some(PinnedServer {
                address: "203.0.113.7".parse().unwrap(),
                path: ServerPath {
                    gateway: Some("192.168.1.1".parse().unwrap()),
                    interface: "en0".to_owned(),
                },
            }),
        }
    }

    #[test]
    fn route_state_round_trips() {
        let state = RouteState {
            boot: Some("boot-1".to_owned()),
            sessions: vec![sample_session()],
        };

        let path = temp_path("state");
        state.save(&path).unwrap();
        let loaded = RouteState::load(&path).unwrap().unwrap();

        assert_eq!(loaded.boot.as_deref(), Some("boot-1"));
        let session = &loaded.sessions[0];
        assert_eq!(session.interface, "utun4");
        assert_eq!(session.routes, sample_session().routes);
        let pinned = session.pinned_server.as_ref().unwrap();
        assert_eq!(pinned.address, "203.0.113.7".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            pinned.path.gateway,
            Some("192.168.1.1".parse::<Ipv4Addr>().unwrap())
        );
        assert_eq!(pinned.path.interface, "en0");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn state_without_pinned_route_round_trips() {
        let state = RouteState {
            boot: None,
            sessions: vec![RouteSession {
                interface: "tun0".to_owned(),
                routes: vec!["10.0.0.0/8".parse().unwrap()],
                pinned_server: None,
            }],
        };

        let path = temp_path("state");
        state.save(&path).unwrap();
        let loaded = RouteState::load(&path).unwrap().unwrap();

        let session = &loaded.sessions[0];
        assert!(session.pinned_server.is_none());
        assert_eq!(session.routes.len(), 1);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn no_cleanup_needed_without_state_file() {
        assert!(cleanup_leftovers(&temp_path("state")).unwrap().is_none());
    }

    #[test]
    fn state_file_is_owner_only() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let path = temp_path("state");
            RouteState::default().save(&path).unwrap();
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            fs::remove_file(&path).unwrap();
        }
    }

    #[test]
    fn persisting_leaves_no_temp_file() {
        let path = temp_path("state");
        let temporary_prefix = format!(".{}.", path.file_name().unwrap().to_string_lossy());
        for _ in 0..2 {
            RouteState {
                boot: boot_id(),
                sessions: vec![sample_session()],
            }
            .save(&path)
            .unwrap();
            // Write a temporary file and rename it; nothing should be left behind, and the final
            // file must be complete and readable.
            assert_eq!(RouteState::load(&path).unwrap().unwrap().sessions.len(), 1);
            let has_temporary = fs::read_dir(path.parent().unwrap()).unwrap().any(|entry| {
                let name = entry.unwrap().file_name();
                let name = name.to_string_lossy();
                name.starts_with(&temporary_prefix) && name.ends_with(".tmp")
            });
            assert!(!has_temporary);
        }
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn records_from_before_reboot_are_discarded() {
        let path = temp_path("state");
        RouteState {
            // Guaranteed to differ from the current boot identifier, simulating a record from a
            // previous boot.
            boot: Some("previous-boot".to_owned()),
            sessions: vec![sample_session()],
        }
        .save(&path)
        .unwrap();

        let report = cleanup_leftovers(&path).unwrap().unwrap();
        assert!(report.rebooted);
        // No route should be deleted: the utun name may already belong to another tunnel.
        assert!(report.removed.is_empty());
        assert!(report.failed.is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn new_session_keeps_unrolled_records() {
        let path = temp_path("state");
        RouteState {
            boot: boot_id(),
            sessions: vec![sample_session()],
        }
        .save(&path)
        .unwrap();

        // A new session gets the same state file, installs its own routes and persists them.
        let mut manager = RouteManager::new("utun9").with_state_file(Some(path.clone()));
        manager
            .installed_routes
            .push("10.1.0.0/16".parse().unwrap());
        manager.persist();
        // Keep Drop away from the real routing table.
        manager.state_path = None;
        manager.installed_routes.clear();
        manager.carried.clear();

        let loaded = RouteState::load(&path).unwrap().unwrap();
        assert_eq!(loaded.sessions.len(), 2);
        assert_eq!(loaded.sessions[0].interface, "utun4");
        assert_eq!(loaded.sessions[1].interface, "utun9");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn records_from_before_reboot_are_not_inherited() {
        let path = temp_path("state");
        RouteState {
            boot: Some("previous-boot".to_owned()),
            sessions: vec![sample_session()],
        }
        .save(&path)
        .unwrap();

        let manager = RouteManager::new("utun9").with_state_file(Some(path.clone()));
        assert!(manager.carried.is_empty());
        std::mem::forget(manager);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn distinguishes_missing_route_from_failed_delete() {
        assert!(!tolerate_missing(Err(anyhow::anyhow!(
            "command route -n delete failed (exit status: 1): delete net 192.168.2.0: gateway utun4: not in table"
        )))
        .unwrap());
        assert!(
            !tolerate_missing(Err(anyhow::anyhow!(
                "command ip failed (exit status: 2): RTNETLINK answers: No such process"
            )))
            .unwrap()
        );
        assert!(tolerate_missing(Ok(())).unwrap());
        assert!(tolerate_missing(Err(anyhow::anyhow!("route: permission denied"))).is_err());
    }

    #[test]
    fn parses_macos_route_output() {
        let path = parse_macos_route_get(
            r#"
               route to: 203.0.113.10
            destination: default
                   mask: default
                gateway: 192.168.1.1
              interface: en0
            "#,
        )
        .unwrap();
        assert_eq!(path.gateway, Some("192.168.1.1".parse().unwrap()));
        assert_eq!(path.interface, "en0");
    }

    #[test]
    fn parses_linux_route_output() {
        let path = parse_linux_route_get(
            "203.0.113.10 via 192.168.1.1 dev eth0 src 192.168.1.10 uid 1000",
        )
        .unwrap();
        assert_eq!(path.gateway, Some("192.168.1.1".parse().unwrap()));
        assert_eq!(path.interface, "eth0");
    }
}
