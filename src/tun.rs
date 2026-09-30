use anyhow::{Context, Result, bail};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;
#[cfg(unix)]
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
#[cfg(unix)]
use tokio::io::unix::AsyncFd;
use tracing::debug;
#[cfg(unix)]
use tracing::trace;

use crate::ppp::NetworkConfig;

pub struct TunDevice {
    #[cfg(unix)]
    fd: AsyncFd<OwnedFd>,
    name: String,
    #[cfg(unix)]
    packet_information: bool,
}

impl TunDevice {
    #[cfg(unix)]
    pub fn create() -> Result<Self> {
        let (fd, name, packet_information) = create_platform_tun()?;
        let fd = AsyncFd::new(fd)
            .context("failed to register the TUN descriptor with the async runtime")?;
        debug!(interface = %name, "TUN interface created");
        Ok(Self {
            fd,
            name,
            packet_information,
        })
    }

    #[cfg(not(unix))]
    pub fn create() -> Result<Self> {
        bail!("no TUN implementation is available on this platform")
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    #[cfg(unix)]
    pub async fn read_packet(&self, buffer: &mut [u8]) -> Result<usize> {
        if self.packet_information {
            let mut framed = vec![0u8; buffer.len() + 4];
            loop {
                let length = self.read_raw(&mut framed).await?;
                if length < 4 {
                    bail!("TUN returned an address family header shorter than 4 bytes");
                }
                let family =
                    u32::from_be_bytes(framed[..4].try_into().expect("length already checked"));
                if family != libc::AF_INET as u32 {
                    trace!(family, "ignoring non-IPv4 packet on TUN");
                    continue;
                }
                let payload_length = length - 4;
                buffer[..payload_length].copy_from_slice(&framed[4..length]);
                return Ok(payload_length);
            }
        }
        // Without an address family header only the IP version can be checked. As soon as the
        // interface is up the kernel sends IPv6 router solicitations and MLD reports on it; the
        // tunnel only carries IPv4, so these must be dropped rather than treated as errors.
        loop {
            let length = self.read_raw(buffer).await?;
            if !is_ipv4_packet(&buffer[..length]) {
                trace!(length, "ignoring non-IPv4 packet on TUN");
                continue;
            }
            return Ok(length);
        }
    }

    #[cfg(not(unix))]
    pub async fn read_packet(&self, _buffer: &mut [u8]) -> Result<usize> {
        bail!("no TUN implementation is available on this platform")
    }

    #[cfg(unix)]
    pub async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        if self.packet_information {
            let mut framed = Vec::with_capacity(packet.len() + 4);
            framed.extend_from_slice(&(libc::AF_INET as u32).to_be_bytes());
            framed.extend_from_slice(packet);
            self.write_raw(&framed).await
        } else {
            self.write_raw(packet).await
        }
    }

    #[cfg(not(unix))]
    pub async fn write_packet(&self, _packet: &[u8]) -> Result<()> {
        bail!("no TUN implementation is available on this platform")
    }

    #[cfg(unix)]
    async fn read_raw(&self, buffer: &mut [u8]) -> Result<usize> {
        loop {
            let mut readiness = self
                .fd
                .readable()
                .await
                .context("failed waiting for TUN to become readable")?;
            match readiness.try_io(|inner| {
                // SAFETY: buffer is valid for the call and the file descriptor is held by OwnedFd.
                let result = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                    )
                };
                if result < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(result as usize)
                }
            }) {
                Ok(result) => {
                    return result.context("failed to read from TUN");
                }
                Err(_would_block) => continue,
            }
        }
    }

    #[cfg(unix)]
    async fn write_raw(&self, packet: &[u8]) -> Result<()> {
        loop {
            let mut readiness = self
                .fd
                .writable()
                .await
                .context("failed waiting for TUN to become writable")?;
            match readiness.try_io(|inner| {
                // SAFETY: packet is valid for the call and the file descriptor is held by OwnedFd.
                let result = unsafe {
                    libc::write(
                        inner.get_ref().as_raw_fd(),
                        packet.as_ptr().cast(),
                        packet.len(),
                    )
                };
                if result < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(result as usize)
                }
            }) {
                Ok(Ok(length)) if length == packet.len() => return Ok(()),
                Ok(Ok(length)) => {
                    bail!(
                        "short write to TUN: expected {} bytes, wrote {length}",
                        packet.len()
                    )
                }
                Ok(Err(error)) => {
                    return Err(error).context("failed to write to TUN");
                }
                Err(_would_block) => continue,
            }
        }
    }
}

/// Checks privileges before starting. Creating a utun on macOS always requires root and no
/// capability can substitute for it; checking early spares the user from typing the password and
/// waiting for the tunnel only to find it cannot run.
#[cfg(target_os = "macos")]
pub fn ensure_privileges() -> Result<()> {
    // SAFETY: geteuid takes no arguments and has no side effects.
    if unsafe { libc::geteuid() } != 0 {
        bail!("creating a macOS utun interface requires root; run barel2tp with sudo");
    }
    Ok(())
}

/// On Linux CAP_NET_ADMIN is enough, so checking the uid would give false negatives; the error is
/// left to TUN creation.
#[cfg(not(target_os = "macos"))]
pub fn ensure_privileges() -> Result<()> {
    Ok(())
}

/// Whether a packet is IPv4: only the version in the high 4 bits of the first byte is checked, and
/// an empty packet counts as non-IPv4.
#[cfg(unix)]
fn is_ipv4_packet(packet: &[u8]) -> bool {
    packet.first().is_some_and(|byte| byte >> 4 == 4)
}

pub fn configure_interface(device: &TunDevice, network: &NetworkConfig, mtu: u16) -> Result<()> {
    configure_platform_interface(device, network, mtu)
}

#[cfg(target_os = "macos")]
fn create_platform_tun() -> Result<(OwnedFd, String, bool)> {
    use std::mem::{size_of, zeroed};

    const SYSPROTO_CONTROL: i32 = 2;
    const AF_SYS_CONTROL: u16 = 2;
    const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;
    const UTUN_OPT_IFNAME: i32 = 2;
    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

    #[repr(C)]
    struct CtlInfo {
        ctl_id: u32,
        ctl_name: [libc::c_char; 96],
    }

    #[repr(C)]
    struct SockaddrCtl {
        sc_len: u8,
        sc_family: u8,
        ss_sysaddr: u16,
        sc_id: u32,
        sc_unit: u32,
        sc_reserved: [u32; 5],
    }

    // SAFETY: the socket arguments come from the public macOS kern_control/utun interface.
    let raw_fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error())
            .context("failed to create the macOS utun control socket");
    }
    // SAFETY: raw_fd is a new file descriptor exclusively owned by this function.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    // SAFETY: both structs contain only integers and character arrays, so zero-initialization is a
    // valid representation.
    let mut info: CtlInfo = unsafe { zeroed() };
    for (target, source) in info
        .ctl_name
        .iter_mut()
        .zip(UTUN_CONTROL_NAME.iter().copied())
    {
        *target = source as libc::c_char;
    }
    // SAFETY: the info pointer and size match the definition of CTLIOCGINFO.
    if unsafe { libc::ioctl(fd.as_raw_fd(), CTLIOCGINFO, &mut info) } < 0 {
        return Err(io::Error::last_os_error())
            .context("failed to look up the macOS utun controller");
    }

    let address = SockaddrCtl {
        sc_len: size_of::<SockaddrCtl>() as u8,
        sc_family: libc::AF_SYSTEM as u8,
        ss_sysaddr: AF_SYS_CONTROL,
        sc_id: info.ctl_id,
        // 0 lets the kernel pick a free utun number.
        sc_unit: 0,
        sc_reserved: [0; 5],
    };
    // SAFETY: the layout of address matches the macOS sockaddr_ctl.
    if unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const SockaddrCtl).cast(),
            size_of::<SockaddrCtl>() as libc::socklen_t,
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::PermissionDenied {
            bail!("creating a macOS utun interface requires root; run barel2tp with sudo");
        }
        return Err(error).context("failed to connect to the macOS utun controller");
    }

    let mut name = [0u8; 64];
    let mut name_length = name.len() as libc::socklen_t;
    // SAFETY: the name buffer and name_length are valid, and the option is defined by if_utun.h.
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &mut name_length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error())
            .context("failed to read the macOS utun interface name");
    }
    let name_end = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name_length as usize)
        .min(name.len());
    let name = std::str::from_utf8(&name[..name_end])
        .context("macOS returned a non-UTF-8 utun interface name")?
        .to_owned();

    set_nonblocking(&fd)?;
    Ok((fd, name, true))
}

#[cfg(target_os = "linux")]
fn create_platform_tun() -> Result<(OwnedFd, String, bool)> {
    use std::{ffi::CStr, mem::zeroed};

    // The ioctl request argument is c_ulong on glibc and c_int on musl. The constants are stored as
    // u32 and converted with `as _` at the call site so the compiler picks the target's type and
    // both libcs compile.
    const TUNSETIFF: u32 = 0x4004_54ca;
    const IFF_TUN: i16 = 0x0001;
    const IFF_NO_PI: i16 = 0x1000;

    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; libc::IFNAMSIZ],
        flags: i16,
        padding: [u8; 22],
    }

    let path = b"/dev/net/tun\0";
    // SAFETY: path is a NUL-terminated string; the new descriptor returned by open is taken over by
    // this function.
    let raw_fd = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDWR | libc::O_NONBLOCK) };
    if raw_fd < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::PermissionDenied {
            bail!("opening /dev/net/tun requires root or CAP_NET_ADMIN; run barel2tp with sudo");
        }
        return Err(error).context("failed to open /dev/net/tun");
    }
    // SAFETY: raw_fd is a new file descriptor exclusively owned by this function.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    // SAFETY: every field of IfReq is valid when zeroed.
    let mut request: IfReq = unsafe { zeroed() };
    request.flags = IFF_TUN | IFF_NO_PI;
    // SAFETY: the leading layout of request matches what Linux ifreq requires for TUNSETIFF.
    if unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, &mut request) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::PermissionDenied {
            bail!(
                "creating a TUN interface requires root or CAP_NET_ADMIN; run barel2tp with sudo"
            );
        }
        return Err(error).context("failed to create TUN via TUNSETIFF");
    }
    // SAFETY: the kernel guarantees ifr_name is a NUL-terminated interface name.
    let name = unsafe { CStr::from_ptr(request.name.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    Ok((fd, name, false))
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn create_platform_tun() -> Result<(OwnedFd, String, bool)> {
    bail!("TUN interfaces are only supported on macOS and Linux")
}

#[cfg(target_os = "macos")]
fn configure_platform_interface(
    device: &TunDevice,
    network: &NetworkConfig,
    mtu: u16,
) -> Result<()> {
    let interface = device.name();
    let peer = network.peer_address.unwrap_or(network.local_address);
    run_command(
        "ifconfig",
        &[
            interface.to_owned(),
            "inet".to_owned(),
            network.local_address.to_string(),
            peer.to_string(),
            "netmask".to_owned(),
            "255.255.255.255".to_owned(),
            "mtu".to_owned(),
            mtu.to_string(),
            "up".to_owned(),
        ],
    )
    .context("failed to configure the macOS utun address")
}

#[cfg(target_os = "linux")]
fn configure_platform_interface(
    device: &TunDevice,
    network: &NetworkConfig,
    mtu: u16,
) -> Result<()> {
    let interface = device.name();
    let mut address_args = vec![
        "addr".to_owned(),
        "replace".to_owned(),
        format!("{}/32", network.local_address),
    ];
    if let Some(peer) = network.peer_address {
        address_args.extend(["peer".to_owned(), format!("{peer}/32")]);
    }
    address_args.extend(["dev".to_owned(), interface.to_owned()]);
    run_command("ip", &address_args).context("failed to configure the Linux TUN address")?;
    run_command(
        "ip",
        &[
            "link".to_owned(),
            "set".to_owned(),
            "dev".to_owned(),
            interface.to_owned(),
            "mtu".to_owned(),
            mtu.to_string(),
            "up".to_owned(),
        ],
    )
    .context("failed to bring up the Linux TUN interface")
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn configure_platform_interface(
    _device: &TunDevice,
    _network: &NetworkConfig,
    _mtu: u16,
) -> Result<()> {
    bail!("TUN interfaces are only supported on macOS and Linux")
}

#[cfg(target_os = "macos")]
fn set_nonblocking(fd: &OwnedFd) -> Result<()> {
    // SAFETY: fcntl only reads and sets flags of a descriptor kept valid by OwnedFd.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error()).context("failed to set TUN to non-blocking mode");
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_command(program: &str, arguments: &[String]) -> Result<()> {
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
            "command {} {} failed ({}): {}",
            program,
            arguments.join(" "),
            output.status,
            stderr
        );
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Fakes a TUN with a pair of local datagram sockets: one end is read by TunDevice and the
    /// other injects packets. SOCK_DGRAM preserves packet boundaries, matching TUN read/write
    /// semantics.
    fn fake_tun_pair() -> (TunDevice, OwnedFd) {
        let mut fds = [0i32; 2];
        // SAFETY: fds has room for two descriptors, and the arguments follow the standard
        // socketpair usage.
        let result =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(result, 0, "socketpair failed");
        // SAFETY: both descriptors were just created and are exclusively owned by this test.
        let (device_fd, peer_fd) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        // SAFETY: the descriptor is valid and fcntl only changes its own status flags.
        let result = unsafe { libc::fcntl(device_fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        assert_eq!(result, 0, "failed to set non-blocking");
        let device = TunDevice {
            fd: AsyncFd::new(device_fd).unwrap(),
            name: "test0".to_owned(),
            packet_information: false,
        };
        (device, peer_fd)
    }

    fn inject(fd: &OwnedFd, packet: &[u8]) {
        // SAFETY: packet is valid for the call and the descriptor is held by the caller.
        let written = unsafe { libc::write(fd.as_raw_fd(), packet.as_ptr().cast(), packet.len()) };
        assert_eq!(
            written,
            packet.len() as isize,
            "failed to write to the fake TUN"
        );
    }

    #[test]
    fn only_version_4_packets_are_ipv4() {
        assert!(is_ipv4_packet(&[0x45, 0x00, 0x00, 0x28]));
        // Once the interface is up the kernel sends IPv6 packets on its own; they must be
        // recognized as non-IPv4.
        assert!(!is_ipv4_packet(&[0x60, 0x00, 0x00, 0x00]));
        assert!(!is_ipv4_packet(&[]));
    }

    /// A Linux TUN has no address family header, so IPv6 packets the kernel sends after the
    /// interface comes up are read directly. They must be dropped: an earlier implementation
    /// treated them as errors and the tunnel broke right after becoming ready.
    #[tokio::test]
    async fn read_skips_ipv6_packets_from_kernel() {
        let (device, peer) = fake_tun_pair();
        inject(&peer, &[0x60, 0x00, 0x00, 0x00, 0x00, 0x08]);
        inject(&peer, &[0x45, 0x00, 0x00, 0x14, 0xde, 0xad]);

        let mut buffer = [0u8; 64];
        let length = device.read_packet(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], &[0x45, 0x00, 0x00, 0x14, 0xde, 0xad]);
    }
}
