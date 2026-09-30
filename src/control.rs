#[cfg(unix)]
use std::path::{Path, PathBuf};

#[cfg(unix)]
use anyhow::Context;
use anyhow::{Result, bail};
#[cfg(unix)]
use tokio::net::UnixDatagram;
#[cfg(unix)]
use tracing::{debug, warn};

/// Unix datagram socket used only by the local GUI to request a disconnect.
#[cfg(unix)]
pub struct ControlSocket {
    socket: UnixDatagram,
    path: PathBuf,
}

#[cfg(unix)]
impl ControlSocket {
    pub fn bind(path: &Path, owner_uid: Option<u32>) -> Result<Self> {
        if path.exists() {
            bail!("control socket already exists: {}", path.display());
        }
        let socket = UnixDatagram::bind(path)
            .with_context(|| format!("failed to create control socket {}", path.display()))?;
        crate::secure_file::set_permissions_nofollow(path, 0o600)
            .context("failed to set control socket permissions")?;

        if let Some(uid) = owner_uid {
            crate::secure_file::chown_nofollow(path, uid)
                .context("failed to hand the control socket to the GUI user")?;
        }

        debug!(path = %path.display(), "local disconnect control socket ready");
        Ok(Self {
            socket,
            path: path.to_owned(),
        })
    }

    pub async fn wait_for_disconnect(&self) -> Result<()> {
        let mut buffer = [0u8; 64];
        loop {
            let length = self
                .socket
                .recv(&mut buffer)
                .await
                .context("failed to read local control command")?;
            if &buffer[..length] == b"disconnect" {
                return Ok(());
            }
            warn!("ignoring unknown local control command");
        }
    }
}

#[cfg(unix)]
impl Drop for ControlSocket {
    fn drop(&mut self) {
        if let Err(error) = crate::secure_file::remove(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %self.path.display(), %error, "failed to remove control socket");
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{os::unix::net::UnixDatagram as StdUnixDatagram, time::SystemTime};

    use super::*;

    #[tokio::test]
    #[ignore = "restricted build sandboxes do not allow creating Unix sockets"]
    async fn receives_gui_disconnect_command() {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("barel2tp-{nonce}.sock"));
        let control = ControlSocket::bind(&path, None).unwrap();
        let sender = StdUnixDatagram::unbound().unwrap();
        sender.send_to(b"disconnect", &path).unwrap();

        control.wait_for_disconnect().await.unwrap();
    }
}

/// Non-Unix platforms have no GUI control socket; command-line connections and Ctrl-C still work.
#[cfg(not(unix))]
pub struct ControlSocket;

#[cfg(not(unix))]
impl ControlSocket {
    pub fn bind(_path: &std::path::Path, _owner_uid: Option<u32>) -> Result<Self> {
        bail!("--control-socket is only available on macOS/Unix")
    }

    pub async fn wait_for_disconnect(&self) -> Result<()> {
        std::future::pending().await
    }
}
