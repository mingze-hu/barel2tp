//! Moves the command-line process into the background: fork/setsid to detach from the controlling
//! terminal, redirect the standard streams, use a PID file for mutual exclusion, and keep the
//! foreground process waiting until the tunnel is really up. The same files are what `--status` and
//! `--stop` rely on.

use std::path::{Path, PathBuf};

use crate::secure_file;
use anyhow::{Context, Result};

#[cfg(unix)]
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};
#[cfg(unix)]
use tracing::warn;

#[cfg(not(unix))]
use anyhow::bail;

/// File name used when `--log-file` is not given.
pub const DEFAULT_LOG_NAME: &str = "barel2tp.log";

/// File name used when `--pid-file` is not given.
pub const DEFAULT_PID_NAME: &str = "barel2tp.pid";

/// File name used when `--state-file` is not given.
pub const DEFAULT_STATE_NAME: &str = "barel2tp.state";

/// Sent by the child to tell the foreground process that the tunnel is ready.
#[cfg(unix)]
const READY_BYTE: u8 = b'1';

/// Permissions of the PID file. A process ID is not a secret, so it is world-readable: the daemon
/// runs as root, but `--status` should work for normal users without sudo.
#[cfg(unix)]
const PID_FILE_MODE: u32 = 0o644;

/// Directory for runtime files when no location is given: the directory of the executable.
///
/// It is used instead of the home directory because background mode usually runs under `sudo`,
/// where the home directory becomes `/var/root` and users cannot find their own log.
pub fn default_runtime_dir() -> Result<PathBuf> {
    let executable = std::env::current_exe().context("cannot locate the executable")?;
    executable
        .parent()
        .map(Path::to_path_buf)
        .context("cannot locate the executable's directory")
}

/// An open log file that also remembers its path, so a failed start can tell the user where to
/// look.
#[cfg(unix)]
pub struct LogTarget {
    file: File,
    path: PathBuf,
}

#[cfg(unix)]
impl LogTarget {
    /// Changes the owner through the securely opened descriptor, avoiding another path lookup that
    /// could follow a symlink.
    pub fn chown_to(&self, uid: u32) -> Result<()> {
        // SAFETY: geteuid cannot fail.
        if unsafe { libc::geteuid() } == uid {
            return Ok(());
        }
        // SAFETY: file holds a valid descriptor; u32::MAX keeps the group unchanged.
        if unsafe { libc::fchown(self.file.as_raw_fd(), uid, u32::MAX) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to hand {} to UID {uid}", self.path.display()));
        }
        Ok(())
    }
}

/// Opens the log file for appending. Called before fork so a wrong path is still reported to the
/// terminal.
#[cfg(unix)]
pub fn open_log_file(path: &Path) -> Result<LogTarget> {
    let file = secure_file::open_append(path, 0o600).with_context(|| {
        format!(
            "failed to open log file {}; use --log-file to choose a writable path",
            path.display()
        )
    })?;
    Ok(LogTarget {
        file,
        path: path.to_owned(),
    })
}

/// Handle held by the daemon; owns the write end of the pipe that notifies the foreground process.
#[cfg(unix)]
pub struct Daemon {
    ready: Option<OwnedFd>,
}

#[cfg(unix)]
impl Daemon {
    /// Tells the waiting foreground process that the tunnel is up and it can exit safely. Only the
    /// first call has any effect.
    pub fn notify_ready(&mut self) {
        let Some(writer) = self.ready.take() else {
            return;
        };
        let mut writer = File::from(writer);
        if let Err(error) = writer.write_all(&[READY_BYTE]) {
            warn!(%error, "failed to notify the foreground process of startup");
        }
    }
}

/// Moves the process into the background. Only the daemon returns from here; the foreground process
/// exits once the tunnel is ready or has failed.
///
/// `fork` keeps only the calling thread and every other thread vanishes in the child, so this
/// **must be called before the tokio runtime is created**, or the daemon's reactor hangs.
///
/// `scrub` runs before the foreground and intermediate processes exit. Both end through `_exit`
/// without running destructors, so the plaintext password copied by `fork` is never wiped by
/// `Zeroizing`; callers must clear their own sensitive data here.
#[cfg(unix)]
pub fn daemonize(log: Option<LogTarget>, scrub: impl FnOnce()) -> Result<Daemon> {
    let log_path = log.as_ref().map(|log| log.path.clone());
    let (reader, writer) = ready_pipe()?;

    // SAFETY: the process is still single-threaded, so the child can keep running ordinary Rust
    // code.
    match unsafe { libc::fork() } {
        -1 => {
            return Err(std::io::Error::last_os_error())
                .context("failed to move to the background");
        }
        0 => {}
        // This branch never continues: wait_for_ready ends the process with _exit.
        _ => {
            drop(writer);
            wait_for_ready(reader, log_path.as_deref(), scrub);
        }
    }
    drop(reader);

    // SAFETY: leaves the original session and controlling terminal, so closing the terminal no
    // longer affects the daemon.
    if unsafe { libc::setsid() } == -1 {
        return Err(std::io::Error::last_os_error())
            .context("failed to detach from the controlling terminal");
    }

    // Fork again: a process that is not a session leader can never reacquire a controlling
    // terminal.
    // SAFETY: as above, the process is still single-threaded.
    match unsafe { libc::fork() } {
        -1 => {
            return Err(std::io::Error::last_os_error())
                .context("failed to move to the background");
        }
        0 => {}
        // The intermediate process exits; the final daemon holds a copy of the write end, so the
        // foreground does not mistake this exit for a failure.
        _ => {
            scrub();
            unsafe { libc::_exit(0) }
        }
    }

    // SAFETY: c"/" is a valid NUL-terminated path; the daemon should not keep any unmountable
    // directory busy.
    if unsafe { libc::chdir(c"/".as_ptr()) } == -1 {
        return Err(std::io::Error::last_os_error())
            .context("failed to change the working directory");
    }
    // SAFETY: umask cannot fail; files created by the daemon are readable and writable only by
    // their owner by default.
    unsafe { libc::umask(0o077) };

    detach_standard_streams(log)?;
    Ok(Daemon {
        ready: Some(writer),
    })
}

/// Connects the log file to stdout and stderr; output from subcommands such as `route` and `ip` is
/// written there too.
#[cfg(unix)]
pub fn redirect_output(log: LogTarget) -> Result<()> {
    replace_standard_stream(&log.file, libc::STDOUT_FILENO)?;
    replace_standard_stream(&log.file, libc::STDERR_FILENO)
}

#[cfg(unix)]
fn detach_standard_streams(log: Option<LogTarget>) -> Result<()> {
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .context("failed to open /dev/null")?;
    replace_standard_stream(&null, libc::STDIN_FILENO)?;
    match log {
        Some(log) => redirect_output(log),
        None => {
            replace_standard_stream(&null, libc::STDOUT_FILENO)?;
            replace_standard_stream(&null, libc::STDERR_FILENO)
        }
    }
}

#[cfg(unix)]
fn replace_standard_stream(file: &File, target: libc::c_int) -> Result<()> {
    // SAFETY: file holds a valid descriptor and target is a standard stream number.
    if unsafe { libc::dup2(file.as_raw_fd(), target) } == -1 {
        return Err(std::io::Error::last_os_error()).context("failed to redirect standard streams");
    }
    Ok(())
}

#[cfg(unix)]
fn ready_pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: fds is an array of length 2, as pipe requires.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } == -1 {
        return Err(std::io::Error::last_os_error())
            .context("failed to create the startup sync pipe");
    }
    // SAFETY: pipe succeeded and both descriptors belong to this process.
    let (reader, writer) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // Subcommands such as route and ip inherit descriptors. Without CLOEXEC, the foreground might
    // never see EOF after the daemon exits because a subcommand still holds the write end.
    set_cloexec(&reader)?;
    set_cloexec(&writer)?;
    Ok((reader, writer))
}

#[cfg(unix)]
fn set_cloexec(fd: &OwnedFd) -> Result<()> {
    // SAFETY: fd is valid; F_GETFD/F_SETFD only read and write descriptor flags.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error()).context("failed to read descriptor flags");
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(std::io::Error::last_os_error()).context("failed to set descriptor flags");
    }
    Ok(())
}

/// The foreground process waits for the daemon's result: the ready byte means success, and EOF
/// means the daemon has already failed and exited.
///
/// `scrub` runs before exiting: `_exit` runs no destructors, so the plaintext password copied by
/// `fork` must be wiped by hand here.
#[cfg(unix)]
fn wait_for_ready(reader: OwnedFd, log_path: Option<&Path>, scrub: impl FnOnce()) -> ! {
    let mut reader = File::from(reader);
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(1) if byte[0] == READY_BYTE => {
                if let Some(path) = log_path {
                    eprintln!(
                        "daemon started; log at {}. Use --status to check it and --stop to stop it",
                        path.display()
                    );
                }
                scrub();
                // SAFETY: exit immediately to avoid running cleanup that belongs to the daemon.
                unsafe { libc::_exit(0) }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            _ => {
                match log_path {
                    Some(path) => {
                        eprintln!("daemon failed to start; see {} for details", path.display());
                    }
                    None => {
                        eprintln!("daemon failed to start; use --log-file to record the reason")
                    }
                }
                scrub();
                // SAFETY: as above.
                unsafe { libc::_exit(1) }
            }
        }
    }
}

/// Reads the process ID recorded in the PID file; returns `None` when the file does not exist.
pub fn read_pid(path: &Path) -> Result<Option<i32>> {
    let source = match secure_file::read_to_string_optional(path) {
        Ok(Some(source)) => source,
        Ok(None) => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(error).with_context(|| {
                format!("permission denied reading PID file {}; the daemon usually runs as root, try sudo", path.display())
            });
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read PID file {}", path.display()));
        }
    };
    parse_pid(&source, path)
}

fn parse_pid(source: &str, path: &Path) -> Result<Option<i32>> {
    let trimmed = source.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let pid: i32 = trimmed
        .parse()
        .with_context(|| format!("PID file {} does not contain a process ID", path.display()))?;
    if pid <= 1 {
        return Ok(None);
    }
    Ok(Some(pid))
}

/// Returns the process ID only while the PID file is still locked by an instance. Stale or replaced
/// files are never trusted by `--stop`, so no signal is sent to a reused PID.
#[cfg(unix)]
pub fn read_running_pid(path: &Path) -> Result<Option<i32>> {
    let Some(mut file) = secure_file::open_read_optional(path)
        .with_context(|| format!("failed to read PID file {}", path.display()))?
    else {
        return Ok(None);
    };

    // Getting the lock means no live instance holds this file; it is only a stale record.
    // SAFETY: file holds a valid descriptor.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        // SAFETY: this function just acquired the lock.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        return Ok(None);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::EWOULDBLOCK) && error.raw_os_error() != Some(libc::EAGAIN)
    {
        return Err(error)
            .with_context(|| format!("failed to check the lock on PID file {}", path.display()));
    }

    let mut source = String::new();
    file.read_to_string(&mut source)
        .with_context(|| format!("failed to read PID file {}", path.display()))?;
    parse_pid(&source, path)
}

/// Whether the process runs as root. Changing the routing table requires it, and checking early
/// avoids "cleanup failed but the records were deleted".
#[cfg(unix)]
pub fn is_root() -> bool {
    // SAFETY: geteuid cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Whether a process is still alive. For another user's process `kill` returns EPERM, which also
/// means it is alive.
#[cfg(unix)]
pub fn process_exists(pid: i32) -> bool {
    // SAFETY: signal 0 only checks permissions and existence; no signal is actually sent.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Asks the daemon to exit gracefully; SIGTERM makes it clean up its routes before ending.
#[cfg(unix)]
pub fn request_stop(pid: i32) -> Result<()> {
    // SAFETY: pid comes from the PID file, and sending SIGTERM does not touch this process's
    // memory.
    if unsafe { libc::kill(pid, libc::SIGTERM) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => anyhow::bail!("process {pid} no longer exists"),
        Some(libc::EPERM) => anyhow::bail!(
            "permission denied stopping process {pid}; the daemon usually needs sudo to stop"
        ),
        _ => Err(error).with_context(|| format!("failed to stop process {pid}")),
    }
}

/// Waits for the instance holding the PID file lock to exit. Polling the process ID alone is not
/// enough, because a PID reused while waiting would make an unrelated process look like it has not
/// stopped.
#[cfg(unix)]
pub fn wait_until_stopped(path: &Path, pid: i32, timeout: Duration) -> Result<bool> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if read_running_pid(path)? != Some(pid) || !process_exists(pid) {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(read_running_pid(path)? != Some(pid) || !process_exists(pid))
}

/// File recording the process ID; a file lock guarantees that only one instance runs per PID file.
#[cfg(unix)]
pub struct PidFile {
    /// The file holding the flock; it must stay open for the lock to remain valid.
    _file: File,
    path: PathBuf,
    identity: (u64, u64),
}

#[cfg(unix)]
impl PidFile {
    pub fn acquire(path: &Path) -> Result<Self> {
        let mut file = secure_file::open_read_write(path, PID_FILE_MODE).with_context(|| {
            format!(
                "failed to create PID file {}; use --pid-file to choose a writable path",
                path.display()
            )
        })?;

        // Use flock instead of O_EXCL: the kernel releases the lock when the process crashes, so no
        // stale file prevents the next start.
        // SAFETY: file holds a valid descriptor.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                anyhow::bail!("another barel2tp instance is running: {}", path.display());
            }
            return Err(error)
                .with_context(|| format!("failed to lock PID file {}", path.display()));
        }

        // The PID file must belong to the running process. Even inside the GUI user's directory,
        // that user only gets read access, so they cannot rewrite a PID still locked by a root
        // process and trick --stop into killing the wrong process.
        // SAFETY: file holds a valid descriptor; geteuid cannot fail, and u32::MAX keeps the group
        // unchanged.
        let owner_uid = unsafe { libc::geteuid() };
        if unsafe { libc::fchown(file.as_raw_fd(), owner_uid, u32::MAX) } != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!("failed to set the owner of PID file {}", path.display())
            });
        }

        file.set_len(0).context("failed to truncate the PID file")?;
        writeln!(file, "{}", std::process::id()).context("failed to write the PID file")?;
        file.flush().context("failed to write the PID file")?;
        let identity = secure_file::identity(&file).context("failed to identify the PID file")?;
        Ok(Self {
            _file: file,
            path: path.to_owned(),
            identity,
        })
    }
}

#[cfg(unix)]
impl Drop for PidFile {
    fn drop(&mut self) {
        match secure_file::remove_if_identity_matches(&self.path, self.identity) {
            Ok(true) | Ok(false) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                warn!(path = %self.path.display(), %error, "failed to remove the PID file")
            }
        }
    }
}

/// Non-Unix platforms are not supported.
#[cfg(not(unix))]
pub struct Daemon;

#[cfg(not(unix))]
impl Daemon {
    pub fn notify_ready(&mut self) {}
}

#[cfg(not(unix))]
pub struct LogTarget;

#[cfg(not(unix))]
pub fn open_log_file(path: &Path) -> Result<LogTarget> {
    bail!(
        "--log-file ({}) is only supported on macOS and Linux",
        path.display()
    )
}

#[cfg(not(unix))]
pub fn daemonize(_log: Option<LogTarget>, _scrub: impl FnOnce()) -> Result<Daemon> {
    bail!("--daemon is only supported on macOS and Linux")
}

#[cfg(not(unix))]
pub fn redirect_output(_log: LogTarget) -> Result<()> {
    bail!("--log-file is only supported on macOS and Linux")
}

#[cfg(not(unix))]
pub struct PidFile;

#[cfg(not(unix))]
impl PidFile {
    pub fn acquire(_path: &Path) -> Result<Self> {
        bail!("--pid-file is only supported on macOS and Linux")
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::testing::temp_path;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn rejects_second_instance_with_same_pid_file() {
        let path = temp_path("pid");
        let first = PidFile::acquire(&path).unwrap();
        let recorded = fs::read_to_string(&path).unwrap();
        assert_eq!(recorded.trim(), std::process::id().to_string());

        assert!(PidFile::acquire(&path).is_err());

        drop(first);
        assert!(!path.exists());
    }

    #[test]
    fn pid_file_can_be_reacquired_after_release() {
        let path = temp_path("pid");
        drop(PidFile::acquire(&path).unwrap());
        let second = PidFile::acquire(&path).unwrap();
        drop(second);
        assert!(!path.exists());
    }

    #[test]
    fn reads_pid_file() {
        let path = temp_path("pid");
        assert_eq!(read_pid(&path).unwrap(), None);

        let holder = PidFile::acquire(&path).unwrap();
        let pid = read_pid(&path).unwrap().unwrap();
        assert_eq!(pid, std::process::id() as i32);
        assert!(process_exists(pid));
        assert_eq!(read_running_pid(&path).unwrap(), Some(pid));
        drop(holder);

        fs::write(&path, format!("{}\n", std::process::id())).unwrap();
        assert_eq!(read_running_pid(&path).unwrap(), None);

        fs::write(&path, "not a number").unwrap();
        assert!(read_pid(&path).is_err());
        fs::write(&path, "  \n").unwrap();
        assert_eq!(read_pid(&path).unwrap(), None);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn pid_file_is_readable_by_other_users() {
        let path = temp_path("pid");
        let holder = PidFile::acquire(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        // A PID file written by root must be readable by normal users, or --status would not work.
        assert_eq!(mode, PID_FILE_MODE);
        drop(holder);
    }

    #[test]
    fn daemon_umask_does_not_restrict_pid_file_permissions() {
        // daemonize sets the umask to 077, which trims the OpenOptions mode down to 0600, and
        // --status would then need sudo to read the file. This reproduces that umask environment.
        // SAFETY: umask cannot fail; it is restored at the end, and the other tests in this file
        // set permissions explicitly, so they are unaffected.
        let previous = unsafe { libc::umask(0o077) };
        let path = temp_path("pid");
        let holder = PidFile::acquire(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        drop(holder);
        // SAFETY: as above.
        unsafe { libc::umask(previous) };

        assert_eq!(mode, PID_FILE_MODE);
    }

    #[test]
    fn reused_pid_file_gets_permissions_fixed() {
        let path = temp_path("pid");
        fs::write(&path, b"1234").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let holder = PidFile::acquire(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, PID_FILE_MODE);
        assert_eq!(read_pid(&path).unwrap(), Some(std::process::id() as i32));
        drop(holder);
    }

    #[test]
    fn handing_log_to_self_keeps_owner() {
        let path = temp_path("own");
        let log = open_log_file(&path).unwrap();
        // SAFETY: geteuid cannot fail.
        log.chown_to(unsafe { libc::geteuid() }).unwrap();
        drop(log);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn default_runtime_dir_is_executable_dir() {
        let directory = default_runtime_dir().unwrap();
        assert!(directory.is_absolute());
        assert!(directory.is_dir());
    }
}
