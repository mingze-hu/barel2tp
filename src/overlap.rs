//! Checks before connecting whether the configured subnets overlap the networks already on this
//! machine.
//!
//! Each address can have only one exit: either the local interface or the tunnel. An overlap is not
//! always wrong, but it causes problems whose cause is hard to see from the error, such as "the
//! route cannot be added", "local devices become unreachable" or "the whole machine loses
//! connectivity". So it is explained before the routing table is touched.

use std::{fmt, net::Ipv4Addr};

use anyhow::{Result, bail};
use ipnet::Ipv4Net;
use tracing::debug;

use crate::route;

/// The subnet of one local network interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalNetwork {
    pub interface: String,
    /// Interface address with its netmask, for example `192.168.2.37/24`.
    pub network: Ipv4Net,
}

/// Next hop of the system default route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultGateway {
    pub address: Ipv4Addr,
    pub interface: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverlapKind {
    /// Identical to a local subnet: the system already has this connected route, so the VPN route
    /// cannot be added.
    Same,
    /// Inside a local subnet: the more specific VPN route sends local devices in that range into
    /// the tunnel.
    Inside,
    /// Contains a local subnet: by longest-prefix match that part still uses the local interface
    /// and never enters the VPN.
    Covers,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Overlap {
    pub route: Ipv4Net,
    pub local: LocalNetwork,
    pub kind: OverlapKind,
    /// The local default gateway captured by this VPN route.
    pub gateway: Option<Ipv4Addr>,
}

impl Overlap {
    /// Whether the connection must be refused: either the route cannot be added at all, or adding
    /// it cuts off the whole machine.
    pub fn is_fatal(&self) -> bool {
        self.kind == OverlapKind::Same || self.gateway.is_some()
    }
}

impl fmt::Display for Overlap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            route,
            local,
            kind,
            gateway,
        } = self;
        let interface = &local.interface;
        let local = local.network.trunc();
        match (kind, gateway) {
            (OverlapKind::Same, _) => write!(
                formatter,
                "route {route} is identical to the local network {local} on {interface}; the system already has \
                 this connected route, so the VPN route cannot be added. List only the remote hosts you need (as /32), \
                 or move the local network to a different subnet"
            ),
            (OverlapKind::Inside, Some(gateway)) => write!(
                formatter,
                "route {route} lies inside the local network {local} on {interface} and contains the local gateway \
                 {gateway}; once connected, all internet traffic would be sent into the tunnel and break. List only \
                 the remote hosts you need (as /32, avoiding the gateway), or move the local network to a different subnet"
            ),
            (OverlapKind::Inside, None) => write!(
                formatter,
                "route {route} lies inside the local network {local} on {interface}; once connected, local devices \
                 at these addresses become unreachable because their traffic goes into the VPN"
            ),
            (OverlapKind::Covers, _) => write!(
                formatter,
                "route {route} contains the local network {local} on {interface}; the {local} part still uses the \
                 local network and does not enter the VPN. To reach remote hosts in that range, add them as /32"
            ),
        }
    }
}

/// Finds every overlap between the configured subnets and the local subnets.
pub fn find_overlaps(
    routes: &[Ipv4Net],
    locals: &[LocalNetwork],
    gateway: Option<&DefaultGateway>,
) -> Vec<Overlap> {
    let mut overlaps = Vec::new();
    for route in routes {
        let route = route.trunc();
        for local in locals {
            let network = local.network.trunc();
            let kind = if route == network {
                OverlapKind::Same
            } else if network.contains(&route) {
                OverlapKind::Inside
            } else if route.contains(&network) {
                OverlapKind::Covers
            } else {
                continue;
            };
            // Only a route more specific than the local subnet can capture the gateway, and the
            // gateway must actually sit on this interface.
            let gateway = gateway
                .filter(|gateway| {
                    kind == OverlapKind::Inside
                        && gateway.interface == local.interface
                        && route.contains(&gateway.address)
                })
                .map(|gateway| gateway.address);
            overlaps.push(Overlap {
                route,
                local: local.clone(),
                kind,
                gateway,
            });
        }
    }
    overlaps
}

/// Checks the configured subnets against the current local networks. Fatal overlaps are returned as
/// errors; the rest are returned as warnings.
///
/// Failing to read local interfaces or the default gateway does not block the connection: the check
/// exists to explain problems early and must not become a failure itself.
pub fn check(routes: &[Ipv4Net]) -> Result<Vec<String>> {
    let locals = match local_networks() {
        Ok(locals) => locals,
        Err(error) => {
            return Ok(vec![format!(
                "cannot read local interface addresses, skipping the overlap check: {error:#}"
            )]);
        }
    };
    let gateway = route::default_gateway();
    debug!(?locals, ?gateway, "local networks");

    let (fatal, warnings): (Vec<_>, Vec<_>) = find_overlaps(routes, &locals, gateway.as_ref())
        .into_iter()
        .partition(Overlap::is_fatal);
    if !fatal.is_empty() {
        let reasons: Vec<String> = fatal.iter().map(ToString::to_string).collect();
        bail!("{}", reasons.join("\n"));
    }
    Ok(warnings.iter().map(ToString::to_string).collect())
}

/// IPv4 subnets of the enabled local interfaces. Loopback and point-to-point interfaces (including
/// other VPN tunnels) do not count as local networks.
#[cfg(unix)]
pub fn local_networks() -> Result<Vec<LocalNetwork>> {
    use std::{ffi::CStr, io};

    use anyhow::Context;

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: the list returned by a successful getifaddrs is freed once by freeifaddrs below.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return Err(io::Error::last_os_error()).context("getifaddrs failed");
    }

    let mut networks = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: cursor points at a node of the list returned by getifaddrs and stays valid until
        // it is freed.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;

        let flags = entry.ifa_flags as libc::c_int;
        if flags & libc::IFF_UP == 0 || flags & (libc::IFF_LOOPBACK | libc::IFF_POINTOPOINT) != 0 {
            continue;
        }
        // SAFETY: both pointers come from the same node and may be null; sockaddr_ipv4 checks that
        // itself.
        let Some(address) = (unsafe { sockaddr_ipv4(entry.ifa_addr, true) }) else {
            continue;
        };
        let Some(netmask) = (unsafe { sockaddr_ipv4(entry.ifa_netmask, false) }) else {
            continue;
        };
        let Ok(network) = Ipv4Net::with_netmask(address, netmask) else {
            continue;
        };
        // A host netmask means this is not a network that can overlap anything.
        if network.prefix_len() == 32 {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated interface name.
        let interface = unsafe { CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();
        networks.push(LocalNetwork { interface, network });
    }
    // SAFETY: head comes from a successful getifaddrs and is freed only once.
    unsafe { libc::freeifaddrs(head) };
    Ok(networks)
}

#[cfg(not(unix))]
pub fn local_networks() -> Result<Vec<LocalNetwork>> {
    bail!("reading local interface addresses is not supported on this platform")
}

/// Reads the IPv4 address out of a sockaddr.
///
/// On BSD systems the netmask sockaddr often has no address family and its length may be truncated
/// to the significant bytes, so the family is not checked for netmasks and missing bytes are
/// treated as 0.
///
/// # Safety
///
/// `pointer` is null or points at a valid sockaddr returned by getifaddrs.
#[cfg(unix)]
unsafe fn sockaddr_ipv4(pointer: *const libc::sockaddr, check_family: bool) -> Option<Ipv4Addr> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees the pointer is valid; the sockaddr header contains at least the
    // family field.
    let header = unsafe { &*pointer };
    if check_family && libc::c_int::from(header.sa_family) != libc::AF_INET {
        return None;
    }

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    let length = usize::from(header.sa_len);
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
    let length = std::mem::size_of::<libc::sockaddr_in>();

    let mut ipv4: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let length = length.min(std::mem::size_of::<libc::sockaddr_in>());
    // SAFETY: copies only the length the sockaddr declares, never more than the destination size.
    unsafe {
        std::ptr::copy_nonoverlapping(pointer.cast::<u8>(), (&raw mut ipv4).cast::<u8>(), length);
    }
    Some(Ipv4Addr::from(u32::from_be(ipv4.sin_addr.s_addr)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(interface: &str, network: &str) -> LocalNetwork {
        LocalNetwork {
            interface: interface.to_owned(),
            network: network.parse().unwrap(),
        }
    }

    fn gateway(address: &str, interface: &str) -> DefaultGateway {
        DefaultGateway {
            address: address.parse().unwrap(),
            interface: interface.to_owned(),
        }
    }

    fn routes(values: &[&str]) -> Vec<Ipv4Net> {
        values.iter().map(|value| value.parse().unwrap()).collect()
    }

    #[test]
    fn identical_subnet_is_fatal() {
        let locals = [local("en0", "192.168.2.37/24")];
        let overlaps = find_overlaps(
            &routes(&["192.168.2.0/24", "192.168.30.0/24"]),
            &locals,
            Some(&gateway("192.168.2.1", "en0")),
        );
        assert_eq!(overlaps.len(), 1);
        assert_eq!(overlaps[0].kind, OverlapKind::Same);
        assert!(overlaps[0].is_fatal());
        // The gateway is not reported again; an identical subnet already explains the problem.
        assert_eq!(overlaps[0].gateway, None);
    }

    #[test]
    fn smaller_subnet_capturing_gateway_is_fatal() {
        let overlaps = find_overlaps(
            &routes(&["192.168.2.0/25"]),
            &[local("en0", "192.168.2.37/24")],
            Some(&gateway("192.168.2.1", "en0")),
        );
        assert_eq!(overlaps[0].kind, OverlapKind::Inside);
        assert_eq!(overlaps[0].gateway, Some("192.168.2.1".parse().unwrap()));
        assert!(overlaps[0].is_fatal());
    }

    #[test]
    fn host_route_avoiding_gateway_is_only_a_warning() {
        let overlaps = find_overlaps(
            &routes(&["192.168.2.10/32"]),
            &[local("en0", "192.168.2.37/24")],
            Some(&gateway("192.168.2.1", "en0")),
        );
        assert_eq!(overlaps[0].kind, OverlapKind::Inside);
        assert!(!overlaps[0].is_fatal());
    }

    #[test]
    fn gateway_on_another_interface_is_not_captured() {
        let overlaps = find_overlaps(
            &routes(&["10.0.0.0/25"]),
            &[local("en0", "192.168.2.37/24"), local("en7", "10.0.0.8/24")],
            Some(&gateway("10.0.0.1", "en0")),
        );
        assert_eq!(overlaps.len(), 1);
        assert!(!overlaps[0].is_fatal());
    }

    #[test]
    fn larger_subnet_is_only_a_warning() {
        let overlaps = find_overlaps(
            &routes(&["192.168.0.0/16"]),
            &[local("en0", "192.168.2.37/24")],
            Some(&gateway("192.168.2.1", "en0")),
        );
        assert_eq!(overlaps[0].kind, OverlapKind::Covers);
        assert!(!overlaps[0].is_fatal());
    }

    #[test]
    fn disjoint_subnets_do_not_overlap() {
        let overlaps = find_overlaps(
            &routes(&["192.168.30.0/24", "10.0.0.0/8"]),
            &[local("en0", "192.168.2.37/24")],
            None,
        );
        assert!(overlaps.is_empty());
    }

    #[test]
    fn route_with_host_bits_is_compared_as_network() {
        let overlaps = find_overlaps(
            &routes(&["192.168.2.5/24"]),
            &[local("en0", "192.168.2.37/24")],
            None,
        );
        assert_eq!(overlaps[0].kind, OverlapKind::Same);
        assert_eq!(overlaps[0].route.to_string(), "192.168.2.0/24");
    }

    #[test]
    fn message_names_interface_and_subnet() {
        let overlap = &find_overlaps(
            &routes(&["192.168.2.0/24"]),
            &[local("en0", "192.168.2.37/24")],
            None,
        )[0];
        let message = overlap.to_string();
        assert!(message.contains("en0"));
        assert!(message.contains("192.168.2.0/24"));
        assert!(message.contains("/32"));
    }

    #[cfg(unix)]
    #[test]
    fn reads_local_interface_subnets() {
        // Interfaces differ between environments, so only check that the call works and returns no
        // host netmasks.
        let networks = local_networks().unwrap();
        assert!(networks.iter().all(|local| local.network.prefix_len() < 32));
    }
}
