use std::{net::Ipv4Addr, time::Duration};

use anyhow::{Context, Result, bail};
use md5::{Digest, Md5};
use rand::random;
use tokio::time::Instant;
use tracing::{debug, info, trace, warn};
use zeroize::Zeroizing;

use crate::l2tp::L2tpClient;

const PROTOCOL_IPV4: u16 = 0x0021;
const PROTOCOL_IPCP: u16 = 0x8021;
const PROTOCOL_LCP: u16 = 0xc021;
const PROTOCOL_CHAP: u16 = 0xc223;

const CONFIGURE_REQUEST: u8 = 1;
const CONFIGURE_ACK: u8 = 2;
const CONFIGURE_NAK: u8 = 3;
const CONFIGURE_REJECT: u8 = 4;
const TERMINATE_REQUEST: u8 = 5;
const TERMINATE_ACK: u8 = 6;
const CODE_REJECT: u8 = 7;
const PROTOCOL_REJECT: u8 = 8;
const ECHO_REQUEST: u8 = 9;
const ECHO_REPLY: u8 = 10;

const CHAP_CHALLENGE: u8 = 1;
const CHAP_RESPONSE: u8 = 2;
const CHAP_SUCCESS: u8 = 3;
const CHAP_FAILURE: u8 = 4;

const LCP_OPTION_MRU: u8 = 1;
const LCP_OPTION_ACCM: u8 = 2;
const LCP_OPTION_AUTH: u8 = 3;
const LCP_OPTION_MAGIC: u8 = 5;
const LCP_OPTION_PFC: u8 = 7;
const LCP_OPTION_ACFC: u8 = 8;

const IPCP_OPTION_COMPRESSION: u8 = 2;
const IPCP_OPTION_ADDRESS: u8 = 3;
const IPCP_OPTION_PRIMARY_DNS: u8 = 129;
const IPCP_OPTION_SECONDARY_DNS: u8 = 131;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkConfig {
    pub local_address: Ipv4Addr,
    pub peer_address: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
}

pub struct PppRuntime {
    username: String,
    secret: Zeroizing<String>,
    magic: u32,
    mtu: u16,
    request_dns: bool,
    timeout: Duration,
    retries: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RuntimeEvent {
    None,
    Ipv4(Vec<u8>),
    NetworkConfig(NetworkConfig),
}

pub async fn negotiate(
    client: &mut L2tpClient,
    username: String,
    secret: Zeroizing<String>,
    mtu: u16,
    request_dns: bool,
    timeout: Duration,
    retries: u32,
) -> Result<(NetworkConfig, PppRuntime)> {
    let magic = random::<u32>();
    let network = {
        let mut negotiator = Negotiator::new(
            client,
            &username,
            secret.as_str(),
            mtu,
            request_dns,
            timeout,
            retries,
            magic,
        );
        negotiator.run().await?
    };
    Ok((
        network,
        PppRuntime {
            username,
            secret,
            magic,
            mtu,
            request_dns,
            timeout,
            retries,
        },
    ))
}

impl PppRuntime {
    pub async fn handle_frame(
        &mut self,
        client: &mut L2tpClient,
        frame: &[u8],
    ) -> Result<RuntimeEvent> {
        let packet = parse_ppp_frame(frame)?;
        trace!(
            protocol = format_args!("0x{:04x}", packet.protocol),
            length = packet.payload.len(),
            "received runtime PPP frame"
        );
        match packet.protocol {
            PROTOCOL_IPV4 => {
                if packet.payload.first().map(|byte| byte >> 4) != Some(4) {
                    warn!("dropping packet with IP version other than 4 in PPP IPv4 protocol");
                    return Ok(RuntimeEvent::None);
                }
                Ok(RuntimeEvent::Ipv4(packet.payload.to_vec()))
            }
            PROTOCOL_LCP => {
                let control = parse_control_packet(packet.payload)?;
                match control.code {
                    ECHO_REQUEST => {
                        let mut data = self.magic.to_be_bytes().to_vec();
                        if control.data.len() > 4 {
                            data.extend_from_slice(&control.data[4..]);
                        }
                        send_control(client, PROTOCOL_LCP, ECHO_REPLY, control.id, &data).await?;
                    }
                    TERMINATE_REQUEST => {
                        send_control(
                            client,
                            PROTOCOL_LCP,
                            TERMINATE_ACK,
                            control.id,
                            control.data,
                        )
                        .await?;
                        bail!("PPP peer requested link termination");
                    }
                    CONFIGURE_REQUEST => {
                        info!(
                            "PPP peer requested LCP renegotiation; pausing IP forwarding and re-authenticating"
                        );
                        let magic = random::<u32>();
                        let network = {
                            let mut negotiator = Negotiator::new(
                                client,
                                &self.username,
                                self.secret.as_str(),
                                self.mtu,
                                self.request_dns,
                                self.timeout,
                                self.retries,
                                magic,
                            );
                            negotiator.run_from_lcp_request(packet.payload).await?
                        };
                        self.magic = magic;
                        info!("runtime LCP/CHAP-MD5/IPCP renegotiation complete");
                        return Ok(RuntimeEvent::NetworkConfig(network));
                    }
                    CODE_REJECT | PROTOCOL_REJECT => {
                        warn!(code = control.code, "PPP peer reported a Protocol-Reject");
                    }
                    _ => {}
                }
                Ok(RuntimeEvent::None)
            }
            PROTOCOL_CHAP => {
                let chap = parse_control_packet(packet.payload)?;
                match chap.code {
                    CHAP_CHALLENGE => {
                        send_chap_response(
                            client,
                            chap.id,
                            chap.data,
                            &self.username,
                            self.secret.as_str(),
                        )
                        .await?;
                        debug!(
                            id = chap.id,
                            "answered runtime CHAP-MD5 re-authentication challenge"
                        );
                    }
                    CHAP_FAILURE => {
                        bail!(
                            "runtime CHAP-MD5 re-authentication failed: {}",
                            display_message(chap.data)
                        );
                    }
                    _ => {}
                }
                Ok(RuntimeEvent::None)
            }
            PROTOCOL_IPCP => {
                let ipcp = parse_control_packet(packet.payload)?;
                match ipcp.code {
                    TERMINATE_REQUEST => {
                        send_control(client, PROTOCOL_IPCP, TERMINATE_ACK, ipcp.id, ipcp.data)
                            .await?;
                        bail!("PPP peer requested IPCP termination");
                    }
                    CONFIGURE_REQUEST => {
                        info!("PPP peer requested IPCP renegotiation; pausing IP forwarding");
                        let network = {
                            let mut negotiator = Negotiator::new(
                                client,
                                &self.username,
                                self.secret.as_str(),
                                self.mtu,
                                self.request_dns,
                                self.timeout,
                                self.retries,
                                self.magic,
                            );
                            negotiator.run_from_ipcp_request(packet.payload).await?
                        };
                        info!("runtime IPCP renegotiation complete");
                        return Ok(RuntimeEvent::NetworkConfig(network));
                    }
                    _ => {}
                }
                Ok(RuntimeEvent::None)
            }
            other => {
                trace!(
                    protocol = format_args!("0x{other:04x}"),
                    "ignoring PPP protocol that is not enabled"
                );
                Ok(RuntimeEvent::None)
            }
        }
    }

    pub async fn send_ipv4(&self, client: &mut L2tpClient, packet: &[u8]) -> Result<()> {
        if packet.first().map(|byte| byte >> 4) != Some(4) {
            bail!("TUN returned a non-IPv4 packet");
        }
        let frame = encode_ppp_frame(PROTOCOL_IPV4, packet);
        client.send_ppp(&frame).await
    }
}

struct Negotiator<'a> {
    client: &'a mut L2tpClient,
    username: &'a str,
    secret: &'a str,
    timeout: Duration,
    retries: u32,
    magic: u32,

    next_id: u8,
    lcp_request_id: u8,
    lcp_options: Vec<u8>,
    lcp_local_acked: bool,
    lcp_peer_acked: bool,
    chap_negotiated: bool,
    chap_succeeded: bool,
    chap_response_id: Option<u8>,

    ipcp_started: bool,
    ipcp_request_id: u8,
    ipcp_options: Vec<(u8, Ipv4Addr)>,
    ipcp_local_acked: bool,
    ipcp_peer_acked: bool,
    local_address: Option<Ipv4Addr>,
    peer_address: Option<Ipv4Addr>,
    dns_servers: Vec<Ipv4Addr>,
}

impl<'a> Negotiator<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        client: &'a mut L2tpClient,
        username: &'a str,
        secret: &'a str,
        mtu: u16,
        request_dns: bool,
        timeout: Duration,
        retries: u32,
        magic: u32,
    ) -> Self {
        let mut lcp_options = Vec::new();
        lcp_options.extend_from_slice(&[LCP_OPTION_MRU, 4]);
        lcp_options.extend_from_slice(&mtu.to_be_bytes());
        lcp_options.extend_from_slice(&[LCP_OPTION_MAGIC, 6]);
        lcp_options.extend_from_slice(&magic.to_be_bytes());

        let mut ipcp_options = vec![(IPCP_OPTION_ADDRESS, Ipv4Addr::UNSPECIFIED)];
        if request_dns {
            ipcp_options.push((IPCP_OPTION_PRIMARY_DNS, Ipv4Addr::UNSPECIFIED));
            ipcp_options.push((IPCP_OPTION_SECONDARY_DNS, Ipv4Addr::UNSPECIFIED));
        }

        Self {
            client,
            username,
            secret,
            timeout,
            retries,
            magic,
            next_id: random(),
            lcp_request_id: 0,
            lcp_options,
            lcp_local_acked: false,
            lcp_peer_acked: false,
            chap_negotiated: false,
            chap_succeeded: false,
            chap_response_id: None,
            ipcp_started: false,
            ipcp_request_id: 0,
            ipcp_options,
            ipcp_local_acked: false,
            ipcp_peer_acked: false,
            local_address: None,
            peer_address: None,
            dns_servers: Vec::new(),
        }
    }

    async fn run(&mut self) -> Result<NetworkConfig> {
        self.restart_lcp_request().await?;
        self.run_loop().await
    }

    async fn run_from_lcp_request(&mut self, request: &[u8]) -> Result<NetworkConfig> {
        self.restart_lcp_request().await?;
        self.handle_lcp(request).await?;
        if self.lcp_open() && !self.chap_negotiated {
            bail!(
                "server did not negotiate the required CHAP-MD5 authentication in the renegotiated LCP"
            );
        }
        self.maybe_start_ipcp().await?;
        self.run_loop().await
    }

    async fn run_from_ipcp_request(&mut self, request: &[u8]) -> Result<NetworkConfig> {
        self.lcp_local_acked = true;
        self.lcp_peer_acked = true;
        self.chap_negotiated = true;
        self.chap_succeeded = true;
        self.ipcp_started = true;
        self.restart_ipcp_request().await?;
        self.handle_ipcp(request).await?;
        self.run_loop().await
    }

    async fn run_loop(&mut self) -> Result<NetworkConfig> {
        let mut consecutive_timeouts = 0u32;
        let mut deadline = Instant::now() + self.timeout;

        loop {
            if self.ipcp_local_acked && self.ipcp_peer_acked {
                let local_address = self
                    .local_address
                    .filter(|address| !address.is_unspecified())
                    .context("IPCP acknowledged, but the server did not assign a valid local IPv4 address")?;
                info!(
                    %local_address,
                    peer_address = ?self.peer_address,
                    dns_servers = ?self.dns_servers,
                    "PPP, CHAP-MD5 and IPCP negotiation complete");
                return Ok(NetworkConfig {
                    local_address,
                    peer_address: self
                        .peer_address
                        .filter(|address| !address.is_unspecified()),
                    dns_servers: self.dns_servers.clone(),
                });
            }

            let frame = match tokio::time::timeout_at(deadline, self.client.recv_ppp()).await {
                Ok(result) => result?,
                Err(_) => {
                    consecutive_timeouts += 1;
                    if consecutive_timeouts > self.retries {
                        bail!(
                            "PPP {} phase timed out after {} waits",
                            self.phase_name(),
                            self.retries
                        );
                    }
                    self.retransmit_current_request().await?;
                    deadline = Instant::now() + self.timeout;
                    continue;
                }
            };

            let progressed = self.handle_frame(&frame).await?;
            if self.lcp_open() && !self.chap_negotiated {
                bail!("server did not negotiate the required CHAP-MD5 authentication in LCP");
            }
            self.maybe_start_ipcp().await?;
            if progressed {
                consecutive_timeouts = 0;
                deadline = Instant::now() + self.timeout;
            }
        }
    }

    fn phase_name(&self) -> &'static str {
        if !self.lcp_open() {
            "LCP"
        } else if !self.chap_succeeded {
            "CHAP-MD5"
        } else {
            "IPCP"
        }
    }

    fn lcp_open(&self) -> bool {
        self.lcp_local_acked && self.lcp_peer_acked
    }

    async fn handle_frame(&mut self, frame: &[u8]) -> Result<bool> {
        let packet = parse_ppp_frame(frame)?;
        trace!(
            protocol = format_args!("0x{:04x}", packet.protocol),
            length = packet.payload.len(),
            phase = self.phase_name(),
            "received PPP negotiation frame"
        );
        match packet.protocol {
            PROTOCOL_LCP => self.handle_lcp(packet.payload).await,
            PROTOCOL_CHAP => self.handle_chap(packet.payload).await,
            PROTOCOL_IPCP if self.chap_succeeded => self.handle_ipcp(packet.payload).await,
            PROTOCOL_IPCP => {
                debug!("ignoring IPCP packet before CHAP-MD5 completes");
                Ok(false)
            }
            PROTOCOL_IPV4 => {
                debug!("ignoring IPv4 packet before IPCP completes");
                Ok(false)
            }
            other => {
                debug!(
                    protocol = format_args!("0x{other:04x}"),
                    "ignoring unknown PPP protocol during negotiation"
                );
                Ok(false)
            }
        }
    }

    async fn handle_lcp(&mut self, payload: &[u8]) -> Result<bool> {
        let packet = parse_control_packet(payload)?;
        match packet.code {
            CONFIGURE_REQUEST => {
                let (code, response, chap_md5) = negotiate_lcp_options(packet.data)?;
                send_control(self.client, PROTOCOL_LCP, code, packet.id, &response).await?;
                let newly_acked = code == CONFIGURE_ACK && !self.lcp_peer_acked;
                self.lcp_peer_acked = code == CONFIGURE_ACK;
                if code == CONFIGURE_ACK {
                    self.chap_negotiated = chap_md5;
                }
                debug!(code, id = packet.id, "answered LCP Configure-Request");
                Ok(newly_acked)
            }
            CONFIGURE_ACK => {
                if packet.id == self.lcp_request_id && packet.data == self.lcp_options {
                    let progressed = !self.lcp_local_acked;
                    self.lcp_local_acked = true;
                    debug!(id = packet.id, "local LCP configuration acknowledged");
                    Ok(progressed)
                } else {
                    debug!(
                        id = packet.id,
                        "ignoring LCP Configure-Ack that does not match the current request"
                    );
                    Ok(false)
                }
            }
            CONFIGURE_NAK => {
                if packet.id != self.lcp_request_id {
                    return Ok(false);
                }
                self.apply_lcp_nak(packet.data)?;
                self.restart_lcp_request().await?;
                Ok(true)
            }
            CONFIGURE_REJECT => {
                if packet.id != self.lcp_request_id {
                    return Ok(false);
                }
                self.apply_lcp_reject(packet.data)?;
                self.restart_lcp_request().await?;
                Ok(true)
            }
            TERMINATE_REQUEST => {
                send_control(
                    self.client,
                    PROTOCOL_LCP,
                    TERMINATE_ACK,
                    packet.id,
                    packet.data,
                )
                .await?;
                bail!("PPP peer terminated LCP during negotiation");
            }
            ECHO_REQUEST => {
                let mut data = self.magic.to_be_bytes().to_vec();
                if packet.data.len() > 4 {
                    data.extend_from_slice(&packet.data[4..]);
                }
                send_control(self.client, PROTOCOL_LCP, ECHO_REPLY, packet.id, &data).await?;
                Ok(false)
            }
            CODE_REJECT | PROTOCOL_REJECT => {
                bail!(
                    "PPP peer returned reject code {} during LCP negotiation",
                    packet.code
                );
            }
            _ => Ok(false),
        }
    }

    async fn handle_chap(&mut self, payload: &[u8]) -> Result<bool> {
        let packet = parse_control_packet(payload)?;
        match packet.code {
            CHAP_CHALLENGE => {
                if !self.chap_negotiated && self.lcp_open() {
                    bail!("server sent a CHAP challenge without negotiating CHAP-MD5 in LCP");
                }
                send_chap_response(
                    self.client,
                    packet.id,
                    packet.data,
                    self.username,
                    self.secret,
                )
                .await?;
                self.chap_response_id = Some(packet.id);
                debug!(id = packet.id, "sent CHAP-MD5 Response");
                Ok(true)
            }
            CHAP_SUCCESS => {
                if self.chap_response_id != Some(packet.id) {
                    debug!(id = packet.id, "ignoring mismatched CHAP Success");
                    return Ok(false);
                }
                let progressed = !self.chap_succeeded;
                self.chap_succeeded = true;
                info!(message = %display_message(packet.data), "CHAP-MD5 authentication succeeded");
                Ok(progressed)
            }
            CHAP_FAILURE => {
                bail!(
                    "CHAP-MD5 authentication failed: {}",
                    display_message(packet.data)
                );
            }
            _ => Ok(false),
        }
    }

    async fn handle_ipcp(&mut self, payload: &[u8]) -> Result<bool> {
        let packet = parse_control_packet(payload)?;
        match packet.code {
            CONFIGURE_REQUEST => {
                let (code, response, peer_address) = negotiate_ipcp_options(packet.data)?;
                send_control(self.client, PROTOCOL_IPCP, code, packet.id, &response).await?;
                let progressed = code == CONFIGURE_ACK && !self.ipcp_peer_acked;
                self.ipcp_peer_acked = code == CONFIGURE_ACK;
                if code == CONFIGURE_ACK {
                    self.peer_address = peer_address;
                }
                debug!(code, id = packet.id, "answered IPCP Configure-Request");
                Ok(progressed)
            }
            CONFIGURE_ACK => {
                let expected = encode_ipcp_options(&self.ipcp_options);
                if packet.id != self.ipcp_request_id || packet.data != expected {
                    debug!(
                        id = packet.id,
                        "ignoring IPCP Configure-Ack that does not match the current request"
                    );
                    return Ok(false);
                }
                self.read_ipcp_assignment(packet.data)?;
                let progressed = !self.ipcp_local_acked;
                self.ipcp_local_acked = true;
                Ok(progressed)
            }
            CONFIGURE_NAK => {
                if packet.id != self.ipcp_request_id {
                    return Ok(false);
                }
                self.apply_ipcp_nak(packet.data)?;
                self.restart_ipcp_request().await?;
                Ok(true)
            }
            CONFIGURE_REJECT => {
                if packet.id != self.ipcp_request_id {
                    return Ok(false);
                }
                self.apply_ipcp_reject(packet.data)?;
                self.restart_ipcp_request().await?;
                Ok(true)
            }
            TERMINATE_REQUEST => {
                send_control(
                    self.client,
                    PROTOCOL_IPCP,
                    TERMINATE_ACK,
                    packet.id,
                    packet.data,
                )
                .await?;
                bail!("PPP peer terminated IPCP negotiation");
            }
            _ => Ok(false),
        }
    }

    async fn maybe_start_ipcp(&mut self) -> Result<()> {
        if !self.lcp_open() || self.ipcp_started || !self.chap_succeeded {
            return Ok(());
        }
        if !self.chap_negotiated {
            bail!("server did not negotiate the required CHAP-MD5 authentication");
        }
        self.ipcp_started = true;
        self.restart_ipcp_request().await
    }

    async fn retransmit_current_request(&mut self) -> Result<()> {
        if !self.lcp_open() {
            if !self.lcp_local_acked {
                self.send_lcp_request().await?;
            }
        } else if !self.chap_succeeded {
            debug!("waiting for the server's CHAP-MD5 Challenge");
        } else if !self.ipcp_local_acked {
            self.send_ipcp_request().await?;
        }
        Ok(())
    }

    async fn restart_lcp_request(&mut self) -> Result<()> {
        self.next_id = self.next_id.wrapping_add(1);
        self.lcp_request_id = self.next_id;
        self.lcp_local_acked = false;
        self.send_lcp_request().await
    }

    async fn send_lcp_request(&mut self) -> Result<()> {
        send_control(
            self.client,
            PROTOCOL_LCP,
            CONFIGURE_REQUEST,
            self.lcp_request_id,
            &self.lcp_options,
        )
        .await
    }

    async fn restart_ipcp_request(&mut self) -> Result<()> {
        self.next_id = self.next_id.wrapping_add(1);
        self.ipcp_request_id = self.next_id;
        self.ipcp_local_acked = false;
        self.send_ipcp_request().await
    }

    async fn send_ipcp_request(&mut self) -> Result<()> {
        let options = encode_ipcp_options(&self.ipcp_options);
        send_control(
            self.client,
            PROTOCOL_IPCP,
            CONFIGURE_REQUEST,
            self.ipcp_request_id,
            &options,
        )
        .await
    }

    fn apply_lcp_nak(&mut self, data: &[u8]) -> Result<()> {
        for option in parse_options(data)? {
            match option[0] {
                LCP_OPTION_MRU if option.len() == 4 => {
                    replace_option(&mut self.lcp_options, LCP_OPTION_MRU, option)?;
                }
                LCP_OPTION_MAGIC if option.len() == 6 => {
                    let mut replacement = vec![LCP_OPTION_MAGIC, 6];
                    replacement.extend_from_slice(&random::<u32>().to_be_bytes());
                    replace_option(&mut self.lcp_options, LCP_OPTION_MAGIC, &replacement)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn apply_lcp_reject(&mut self, data: &[u8]) -> Result<()> {
        for option in parse_options(data)? {
            remove_option(&mut self.lcp_options, option[0])?;
        }
        Ok(())
    }

    fn read_ipcp_assignment(&mut self, data: &[u8]) -> Result<()> {
        self.dns_servers.clear();
        for option in parse_options(data)? {
            let address = option_ipv4(option)?;
            match option[0] {
                IPCP_OPTION_ADDRESS => self.local_address = Some(address),
                IPCP_OPTION_PRIMARY_DNS | IPCP_OPTION_SECONDARY_DNS
                    if !address.is_unspecified() =>
                {
                    self.dns_servers.push(address);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn apply_ipcp_nak(&mut self, data: &[u8]) -> Result<()> {
        for option in parse_options(data)? {
            if matches!(
                option[0],
                IPCP_OPTION_ADDRESS | IPCP_OPTION_PRIMARY_DNS | IPCP_OPTION_SECONDARY_DNS
            ) && option.len() == 6
            {
                let address = option_ipv4(option)?;
                if let Some((_, current)) = self
                    .ipcp_options
                    .iter_mut()
                    .find(|(kind, _)| *kind == option[0])
                {
                    *current = address;
                }
            }
        }
        Ok(())
    }

    fn apply_ipcp_reject(&mut self, data: &[u8]) -> Result<()> {
        for option in parse_options(data)? {
            if option[0] == IPCP_OPTION_ADDRESS {
                bail!("server rejected the IPCP IP-Address option; cannot obtain a tunnel address");
            }
            self.ipcp_options.retain(|(kind, _)| *kind != option[0]);
        }
        Ok(())
    }
}

fn negotiate_lcp_options(data: &[u8]) -> Result<(u8, Vec<u8>, bool)> {
    let options = parse_options(data)?;
    let mut rejected = Vec::new();
    let mut nak = Vec::new();
    let mut chap_md5 = false;

    for option in options {
        let valid = match option[0] {
            LCP_OPTION_MRU => option.len() == 4,
            LCP_OPTION_ACCM => option.len() == 6,
            LCP_OPTION_MAGIC => option.len() == 6,
            LCP_OPTION_PFC | LCP_OPTION_ACFC => option.len() == 2,
            LCP_OPTION_AUTH => {
                if option == [LCP_OPTION_AUTH, 5, 0xc2, 0x23, 5] {
                    chap_md5 = true;
                    true
                } else {
                    nak.extend_from_slice(&[LCP_OPTION_AUTH, 5, 0xc2, 0x23, 5]);
                    true
                }
            }
            _ => false,
        };
        if !valid {
            rejected.extend_from_slice(option);
        }
    }

    if !rejected.is_empty() {
        Ok((CONFIGURE_REJECT, rejected, false))
    } else if !nak.is_empty() {
        Ok((CONFIGURE_NAK, nak, false))
    } else {
        Ok((CONFIGURE_ACK, data.to_vec(), chap_md5))
    }
}

fn negotiate_ipcp_options(data: &[u8]) -> Result<(u8, Vec<u8>, Option<Ipv4Addr>)> {
    let options = parse_options(data)?;
    let mut rejected = Vec::new();
    let mut peer_address = None;
    for option in options {
        match option[0] {
            IPCP_OPTION_ADDRESS if option.len() == 6 => {
                peer_address = Some(option_ipv4(option)?);
            }
            IPCP_OPTION_COMPRESSION => rejected.extend_from_slice(option),
            _ => rejected.extend_from_slice(option),
        }
    }
    if rejected.is_empty() {
        Ok((CONFIGURE_ACK, data.to_vec(), peer_address))
    } else {
        Ok((CONFIGURE_REJECT, rejected, None))
    }
}

async fn send_chap_response(
    client: &mut L2tpClient,
    id: u8,
    challenge_data: &[u8],
    username: &str,
    secret: &str,
) -> Result<()> {
    let (&value_size, rest) = challenge_data
        .split_first()
        .context("CHAP Challenge is missing Value-Size")?;
    let value_size = value_size as usize;
    if value_size == 0 || rest.len() < value_size {
        bail!("invalid CHAP Challenge Value length");
    }
    let challenge = &rest[..value_size];

    let mut md5 = Md5::new();
    md5.update([id]);
    md5.update(secret.as_bytes());
    md5.update(challenge);
    let digest = md5.finalize();

    let mut response = Vec::with_capacity(1 + digest.len() + username.len());
    response.push(digest.len() as u8);
    response.extend_from_slice(&digest);
    response.extend_from_slice(username.as_bytes());
    send_control(client, PROTOCOL_CHAP, CHAP_RESPONSE, id, &response).await
}

async fn send_control(
    client: &mut L2tpClient,
    protocol: u16,
    code: u8,
    id: u8,
    data: &[u8],
) -> Result<()> {
    let length: u16 = (4usize + data.len())
        .try_into()
        .context("PPP control packet exceeds 65535 bytes")?;
    let mut payload = Vec::with_capacity(length as usize);
    payload.push(code);
    payload.push(id);
    payload.extend_from_slice(&length.to_be_bytes());
    payload.extend_from_slice(data);
    client.send_ppp(&encode_ppp_frame(protocol, &payload)).await
}

fn encode_ppp_frame(protocol: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&[0xff, 0x03]);
    frame.extend_from_slice(&protocol.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

struct PppPacket<'a> {
    protocol: u16,
    payload: &'a [u8],
}

fn parse_ppp_frame(frame: &[u8]) -> Result<PppPacket<'_>> {
    let mut cursor = if frame.starts_with(&[0xff, 0x03]) {
        2
    } else {
        0
    };
    let first = *frame
        .get(cursor)
        .context("PPP frame is missing the Protocol field")?;
    let protocol = if first & 1 != 0 {
        cursor += 1;
        first as u16
    } else {
        let second = *frame
            .get(cursor + 1)
            .context("truncated PPP Protocol field")?;
        cursor += 2;
        u16::from_be_bytes([first, second])
    };
    if protocol & 1 == 0 {
        bail!("lowest bit of the PPP Protocol field is not 1");
    }
    Ok(PppPacket {
        protocol,
        payload: &frame[cursor..],
    })
}

struct ControlPacket<'a> {
    code: u8,
    id: u8,
    data: &'a [u8],
}

fn parse_control_packet(payload: &[u8]) -> Result<ControlPacket<'_>> {
    if payload.len() < 4 {
        bail!("PPP control packet is shorter than 4 bytes");
    }
    let length = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if length < 4 || length > payload.len() {
        bail!("invalid PPP control packet Length field");
    }
    Ok(ControlPacket {
        code: payload[0],
        id: payload[1],
        data: &payload[4..length],
    })
}

fn parse_options(mut data: &[u8]) -> Result<Vec<&[u8]>> {
    let mut options = Vec::new();
    while !data.is_empty() {
        if data.len() < 2 {
            bail!("truncated PPP configuration option header");
        }
        let length = data[1] as usize;
        if length < 2 || length > data.len() {
            bail!("invalid PPP configuration option length");
        }
        options.push(&data[..length]);
        data = &data[length..];
    }
    Ok(options)
}

fn replace_option(options: &mut Vec<u8>, kind: u8, replacement: &[u8]) -> Result<()> {
    remove_option(options, kind)?;
    options.extend_from_slice(replacement);
    Ok(())
}

fn remove_option(options: &mut Vec<u8>, kind: u8) -> Result<()> {
    let retained: Vec<u8> = parse_options(options)?
        .into_iter()
        .filter(|option| option[0] != kind)
        .flat_map(|option| option.iter().copied())
        .collect();
    *options = retained;
    Ok(())
}

fn encode_ipcp_options(options: &[(u8, Ipv4Addr)]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(options.len() * 6);
    for (kind, address) in options {
        encoded.extend_from_slice(&[*kind, 6]);
        encoded.extend_from_slice(&address.octets());
    }
    encoded
}

fn option_ipv4(option: &[u8]) -> Result<Ipv4Addr> {
    if option.len() != 6 {
        bail!("IPCP IPv4 address option length is not 6");
    }
    Ok(Ipv4Addr::new(option[2], option[3], option[4], option[5]))
}

fn display_message(data: &[u8]) -> String {
    let message = String::from_utf8_lossy(data);
    let trimmed = message.trim_matches(|character: char| character.is_control());
    if trimmed.is_empty() {
        "no message from server".to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ppp_frame_supports_standard_and_compressed_protocol_field() {
        let standard = encode_ppp_frame(PROTOCOL_IPV4, &[0x45, 0, 0, 20]);
        let parsed = parse_ppp_frame(&standard).unwrap();
        assert_eq!(parsed.protocol, PROTOCOL_IPV4);
        assert_eq!(parsed.payload, [0x45, 0, 0, 20]);

        let compressed = [0x21, 0x45, 0, 0, 20];
        let parsed = parse_ppp_frame(&compressed).unwrap();
        assert_eq!(parsed.protocol, PROTOCOL_IPV4);
    }

    #[test]
    fn chap_md5_follows_rfc_concatenation_order() {
        let id = 7u8;
        let secret = b"password";
        let challenge = b"0123456789abcdef";
        let mut digest = Md5::new();
        digest.update([id]);
        digest.update(secret);
        digest.update(challenge);
        let actual = digest.finalize();

        let expected = [
            0x31, 0x36, 0x08, 0xbf, 0x32, 0x47, 0x67, 0x17, 0x4f, 0x79, 0x73, 0xf3, 0x1f, 0x83,
            0x31, 0x42,
        ];
        assert_eq!(actual[..], expected);
    }

    #[test]
    fn accepts_only_chap_md5_auth_option() {
        let chap = [LCP_OPTION_AUTH, 5, 0xc2, 0x23, 5];
        let (code, response, negotiated) = negotiate_lcp_options(&chap).unwrap();
        assert_eq!(code, CONFIGURE_ACK);
        assert_eq!(response, chap);
        assert!(negotiated);

        let pap = [LCP_OPTION_AUTH, 4, 0xc0, 0x23];
        let (code, response, negotiated) = negotiate_lcp_options(&pap).unwrap();
        assert_eq!(code, CONFIGURE_NAK);
        assert_eq!(response, chap);
        assert!(!negotiated);
    }

    #[test]
    fn ipcp_rejects_ip_compression() {
        let options = [
            IPCP_OPTION_ADDRESS,
            6,
            10,
            0,
            0,
            1,
            IPCP_OPTION_COMPRESSION,
            6,
            0,
            0x2d,
            0,
            15,
        ];
        let (code, rejected, peer) = negotiate_ipcp_options(&options).unwrap();
        assert_eq!(code, CONFIGURE_REJECT);
        assert_eq!(rejected, options[6..]);
        assert_eq!(peer, None);
    }
}
