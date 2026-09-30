use std::{
    collections::VecDeque,
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use rand::random;
use tokio::{net::UdpSocket, time::Instant};
use tracing::{debug, info, trace, warn};

const FLAG_TYPE: u16 = 0x8000;
const FLAG_LENGTH: u16 = 0x4000;
const FLAG_SEQUENCE: u16 = 0x0800;
const FLAG_OFFSET: u16 = 0x0200;
const VERSION_2: u16 = 0x0002;
const CONTROL_FLAGS: u16 = FLAG_TYPE | FLAG_LENGTH | FLAG_SEQUENCE | VERSION_2;

const AVP_MESSAGE_TYPE: u16 = 0;
const AVP_RESULT_CODE: u16 = 1;
const AVP_PROTOCOL_VERSION: u16 = 2;
const AVP_FRAMING_CAPABILITIES: u16 = 3;
const AVP_BEARER_CAPABILITIES: u16 = 4;
const AVP_HOST_NAME: u16 = 7;
const AVP_VENDOR_NAME: u16 = 8;
const AVP_ASSIGNED_TUNNEL_ID: u16 = 9;
const AVP_RECEIVE_WINDOW_SIZE: u16 = 10;
const AVP_CHALLENGE: u16 = 11;
const AVP_ASSIGNED_SESSION_ID: u16 = 14;
const AVP_CALL_SERIAL_NUMBER: u16 = 15;
const AVP_BEARER_TYPE: u16 = 18;
const AVP_FRAMING_TYPE: u16 = 19;
const AVP_TX_CONNECT_SPEED: u16 = 24;

const MSG_SCCRQ: u16 = 1;
const MSG_SCCRP: u16 = 2;
const MSG_SCCCN: u16 = 3;
const MSG_STOP_CCN: u16 = 4;
const MSG_HELLO: u16 = 6;
const MSG_ICRQ: u16 = 10;
const MSG_ICRP: u16 = 11;
const MSG_ICCN: u16 = 12;
const MSG_CDN: u16 = 14;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Avp {
    mandatory: bool,
    hidden: bool,
    vendor_id: u16,
    attribute: u16,
    value: Vec<u8>,
}

impl Avp {
    fn bytes(attribute: u16, value: impl Into<Vec<u8>>) -> Self {
        Self {
            mandatory: true,
            hidden: false,
            vendor_id: 0,
            attribute,
            value: value.into(),
        }
    }

    fn u16(attribute: u16, value: u16) -> Self {
        Self::bytes(attribute, value.to_be_bytes())
    }

    fn u32(attribute: u16, value: u32) -> Self {
        Self::bytes(attribute, value.to_be_bytes())
    }

    fn encode(&self, target: &mut Vec<u8>) -> Result<()> {
        let length = 6usize
            .checked_add(self.value.len())
            .context("L2TP AVP length overflow")?;
        if length > 0x03ff {
            bail!("L2TP AVP exceeds 1023 bytes");
        }
        let mut flags_length = length as u16;
        if self.mandatory {
            flags_length |= 0x8000;
        }
        if self.hidden {
            flags_length |= 0x4000;
        }
        target.extend_from_slice(&flags_length.to_be_bytes());
        target.extend_from_slice(&self.vendor_id.to_be_bytes());
        target.extend_from_slice(&self.attribute.to_be_bytes());
        target.extend_from_slice(&self.value);
        Ok(())
    }
}

#[derive(Debug)]
struct ControlFrame {
    tunnel_id: u16,
    session_id: u16,
    ns: u16,
    nr: u16,
    avps: Vec<Avp>,
}

impl ControlFrame {
    /// RFC 2661 requires an unrecognized mandatory AVP to terminate the tunnel; it must not be
    /// silently ignored.
    fn validate_mandatory_avps(&self) -> Result<()> {
        for avp in self.avps.iter().filter(|avp| avp.mandatory) {
            if avp.hidden {
                bail!(
                    "received a hidden mandatory L2TP AVP (Vendor {}, Attribute {}) but no tunnel secret is configured",
                    avp.vendor_id,
                    avp.attribute
                );
            }
            if avp.vendor_id != 0 || !supported_standard_avp(avp.attribute) {
                bail!(
                    "received an unrecognized mandatory L2TP AVP (Vendor {}, Attribute {})",
                    avp.vendor_id,
                    avp.attribute
                );
            }
        }
        Ok(())
    }

    fn message_type(&self) -> Result<Option<u16>> {
        let Some(avp) = self
            .avps
            .iter()
            .find(|avp| avp.vendor_id == 0 && avp.attribute == AVP_MESSAGE_TYPE)
        else {
            return Ok(None);
        };
        if avp.hidden {
            bail!("hidden Message Type AVP is not supported");
        }
        if avp.value.len() != 2 {
            bail!("invalid Message Type AVP length");
        }
        Ok(Some(u16::from_be_bytes([avp.value[0], avp.value[1]])))
    }

    fn avp(&self, attribute: u16) -> Option<&Avp> {
        self.avps
            .iter()
            .find(|avp| avp.vendor_id == 0 && avp.attribute == attribute)
    }

    fn required_u16(&self, attribute: u16, name: &str) -> Result<u16> {
        let avp = self
            .avp(attribute)
            .with_context(|| format!("server response is missing the {name} AVP"))?;
        if avp.hidden {
            bail!("server returned a hidden {name} AVP but no L2TP tunnel secret is configured");
        }
        if avp.value.len() != 2 {
            bail!("server returned an invalid {name} AVP length");
        }
        Ok(u16::from_be_bytes([avp.value[0], avp.value[1]]))
    }

    fn optional_u32(&self, attribute: u16, name: &str) -> Result<Option<u32>> {
        let Some(avp) = self.avp(attribute) else {
            return Ok(None);
        };
        if avp.hidden {
            bail!("server returned a hidden {name} AVP but no L2TP tunnel secret is configured");
        }
        if avp.value.len() != 4 {
            bail!("server returned an invalid {name} AVP length");
        }
        Ok(Some(u32::from_be_bytes(
            avp.value
                .as_slice()
                .try_into()
                .expect("length already checked"),
        )))
    }
}

#[derive(Debug)]
struct DataFrame {
    tunnel_id: u16,
    session_id: u16,
    ns: Option<u16>,
    nr: Option<u16>,
    payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
enum DataSequence {
    Expected,
    Ahead { missing: u16 },
    DuplicateOrLate,
}

#[derive(Debug)]
enum Packet {
    Control(ControlFrame),
    Data(DataFrame),
}

struct ExchangeRequest {
    message_type: u16,
    tunnel_id: u16,
    session_id: u16,
    avps: Vec<Avp>,
    expected_message: Option<u16>,
}

/// One L2TPv2 tunnel and the single PPP session inside it.
pub struct L2tpClient {
    socket: UdpSocket,
    peer: SocketAddrV4,
    local_tunnel_id: u16,
    remote_tunnel_id: u16,
    local_session_id: u16,
    remote_session_id: u16,
    control_tx_ns: u16,
    control_rx_next: u16,
    data_tx_ns: u16,
    data_rx_next: u16,
    use_data_sequence: bool,
    pending_data: VecDeque<DataFrame>,
    receive_buffer: Vec<u8>,
}

impl L2tpClient {
    pub async fn connect(
        peer: SocketAddrV4,
        local_bind: Option<Ipv4Addr>,
        local_port: u16,
    ) -> Result<Self> {
        let local = SocketAddrV4::new(local_bind.unwrap_or(Ipv4Addr::UNSPECIFIED), local_port);
        let socket = UdpSocket::bind(local)
            .await
            .with_context(|| format!("failed to bind local L2TP UDP address {local}"))?;
        socket
            .connect(peer)
            .await
            .with_context(|| format!("failed to connect to L2TP server {peer}"))?;

        let local_tunnel_id = random_nonzero_u16();
        let local_session_id = random_nonzero_u16();
        info!(%peer, local_tunnel_id, local_session_id, "establishing bare L2TPv2 tunnel");

        Ok(Self {
            socket,
            peer,
            local_tunnel_id,
            remote_tunnel_id: 0,
            local_session_id,
            remote_session_id: 0,
            control_tx_ns: 0,
            control_rx_next: 0,
            data_tx_ns: 0,
            data_rx_next: 0,
            use_data_sequence: false,
            pending_data: VecDeque::new(),
            receive_buffer: vec![0; u16::MAX as usize + 1],
        })
    }

    pub fn peer(&self) -> SocketAddrV4 {
        self.peer
    }

    pub async fn establish(
        &mut self,
        hostname: &str,
        timeout: Duration,
        retries: u32,
    ) -> Result<()> {
        let sccrp = self
            .exchange(
                ExchangeRequest {
                    message_type: MSG_SCCRQ,
                    tunnel_id: 0,
                    session_id: 0,
                    avps: vec![
                        Avp::bytes(AVP_PROTOCOL_VERSION, [1, 0]),
                        Avp::u32(AVP_FRAMING_CAPABILITIES, 3),
                        Avp::bytes(AVP_HOST_NAME, hostname.as_bytes()),
                        Avp::bytes(AVP_VENDOR_NAME, b"barel2tp".as_slice()),
                        Avp::u16(AVP_ASSIGNED_TUNNEL_ID, self.local_tunnel_id),
                        Avp::u16(AVP_RECEIVE_WINDOW_SIZE, 4),
                    ],
                    expected_message: Some(MSG_SCCRP),
                },
                timeout,
                retries,
            )
            .await
            .context("SCCRQ/SCCRP tunnel negotiation failed")?;

        self.validate_control_destination(&sccrp)?;
        if sccrp.session_id != 0 {
            bail!("SCCRP destination Session ID must be 0");
        }
        if sccrp.avp(AVP_CHALLENGE).is_some() {
            bail!(
                "server requires L2TP tunnel authentication, but only a PPP CHAP-MD5 password is configured"
            );
        }
        if let Some(capabilities) =
            sccrp.optional_u32(AVP_BEARER_CAPABILITIES, "Bearer Capabilities")?
        {
            debug!(capabilities, "server reported L2TP Bearer Capabilities");
        }
        self.remote_tunnel_id = sccrp.required_u16(AVP_ASSIGNED_TUNNEL_ID, "Assigned Tunnel ID")?;
        if self.remote_tunnel_id == 0 {
            bail!("server assigned an invalid zero Tunnel ID");
        }
        debug!(
            remote_tunnel_id = self.remote_tunnel_id,
            "L2TP control tunnel negotiated"
        );

        self.exchange(
            ExchangeRequest {
                message_type: MSG_SCCCN,
                tunnel_id: self.remote_tunnel_id,
                session_id: 0,
                avps: vec![],
                expected_message: None,
            },
            timeout,
            retries,
        )
        .await
        .context("SCCCN was not acknowledged by the server")?;

        let icrp = self
            .exchange(
                ExchangeRequest {
                    message_type: MSG_ICRQ,
                    tunnel_id: self.remote_tunnel_id,
                    session_id: 0,
                    avps: vec![
                        Avp::u16(AVP_ASSIGNED_SESSION_ID, self.local_session_id),
                        Avp::u32(AVP_CALL_SERIAL_NUMBER, random()),
                        Avp::u32(AVP_BEARER_TYPE, 3),
                    ],
                    expected_message: Some(MSG_ICRP),
                },
                timeout,
                retries,
            )
            .await
            .context("ICRQ/ICRP session negotiation failed")?;
        self.validate_control_destination(&icrp)?;
        if icrp.session_id != self.local_session_id {
            bail!(
                "ICRP destination Session ID mismatch: got {}, expected {}",
                icrp.session_id,
                self.local_session_id
            );
        }
        self.remote_session_id =
            icrp.required_u16(AVP_ASSIGNED_SESSION_ID, "Assigned Session ID")?;
        if self.remote_session_id == 0 {
            bail!("server assigned an invalid zero Session ID");
        }

        self.exchange(
            ExchangeRequest {
                message_type: MSG_ICCN,
                tunnel_id: self.remote_tunnel_id,
                session_id: self.remote_session_id,
                avps: vec![
                    Avp::u32(AVP_TX_CONNECT_SPEED, 100_000_000),
                    Avp::u32(AVP_FRAMING_TYPE, 1),
                ],
                expected_message: None,
            },
            timeout,
            retries,
        )
        .await
        .context("ICCN was not acknowledged by the server")?;

        info!(
            remote_tunnel_id = self.remote_tunnel_id,
            remote_session_id = self.remote_session_id,
            "L2TPv2 session established"
        );
        Ok(())
    }

    /// Sends a reliable L2TP HELLO and waits for the peer to acknowledge it.
    pub async fn send_hello(&mut self, timeout: Duration, retries: u32) -> Result<()> {
        if self.remote_tunnel_id == 0 {
            bail!("L2TP control tunnel is not established yet");
        }
        debug!("L2TP control channel idle, sending HELLO keepalive");
        self.exchange(
            ExchangeRequest {
                message_type: MSG_HELLO,
                tunnel_id: self.remote_tunnel_id,
                session_id: 0,
                avps: vec![],
                expected_message: None,
            },
            timeout,
            retries,
        )
        .await
        .context("L2TP HELLO was not acknowledged by the server")?;
        trace!("L2TP HELLO acknowledged");
        Ok(())
    }

    pub async fn send_ppp(&mut self, ppp_frame: &[u8]) -> Result<()> {
        if self.remote_tunnel_id == 0 || self.remote_session_id == 0 {
            bail!("L2TP session is not established yet");
        }

        let mut packet = Vec::with_capacity(10 + ppp_frame.len());
        if self.use_data_sequence {
            packet.extend_from_slice(&(FLAG_SEQUENCE | VERSION_2).to_be_bytes());
            packet.extend_from_slice(&self.remote_tunnel_id.to_be_bytes());
            packet.extend_from_slice(&self.remote_session_id.to_be_bytes());
            packet.extend_from_slice(&self.data_tx_ns.to_be_bytes());
            packet.extend_from_slice(&self.data_rx_next.to_be_bytes());
            self.data_tx_ns = self.data_tx_ns.wrapping_add(1);
        } else {
            packet.extend_from_slice(&VERSION_2.to_be_bytes());
            packet.extend_from_slice(&self.remote_tunnel_id.to_be_bytes());
            packet.extend_from_slice(&self.remote_session_id.to_be_bytes());
        }
        packet.extend_from_slice(ppp_frame);
        self.socket
            .send(&packet)
            .await
            .context("failed to send L2TP datagram")?;
        trace!(length = ppp_frame.len(), "sent PPP frame");
        Ok(())
    }

    pub async fn recv_ppp(&mut self) -> Result<Vec<u8>> {
        loop {
            let packet = match self.pending_data.pop_front() {
                Some(frame) => Packet::Data(frame),
                None => self.receive_one().await?,
            };
            match packet {
                Packet::Data(frame) => {
                    if frame.tunnel_id != self.local_tunnel_id
                        || frame.session_id != self.local_session_id
                    {
                        debug!(
                            tunnel_id = frame.tunnel_id,
                            session_id = frame.session_id,
                            "ignoring L2TP datagram for another session"
                        );
                        continue;
                    }

                    match (frame.ns, frame.nr) {
                        (Some(ns), Some(_nr)) => {
                            self.use_data_sequence = true;
                            match classify_data_sequence(self.data_rx_next, ns) {
                                DataSequence::Expected => {}
                                DataSequence::Ahead { missing } => {
                                    warn!(
                                        ns,
                                        expected = self.data_rx_next,
                                        missing,
                                        "gap in L2TP data sequence; skipping lost packets and continuing"
                                    );
                                }
                                DataSequence::DuplicateOrLate => {
                                    debug!(
                                        ns,
                                        expected = self.data_rx_next,
                                        "dropping duplicate or late L2TP datagram"
                                    );
                                    continue;
                                }
                            }
                            self.data_rx_next = ns.wrapping_add(1);
                        }
                        _ => self.use_data_sequence = false,
                    }
                    return Ok(frame.payload);
                }
                Packet::Control(frame) => {
                    if !self.control_destination_matches(&frame) {
                        debug!(
                            tunnel_id = frame.tunnel_id,
                            session_id = frame.session_id,
                            "ignoring L2TP control message addressed to another tunnel"
                        );
                        continue;
                    }
                    frame.validate_mandatory_avps()?;
                    let message_type = frame.message_type()?;
                    trace!(
                        message_type = ?message_type,
                        ns = frame.ns,
                        nr = frame.nr,
                        "received L2TP control message");
                    let accepted = self.accept_control(&frame, message_type.is_some());
                    // A ZLB consumes no sequence number and must not be answered with another ZLB,
                    // or the acknowledgements would loop.
                    if message_type.is_some() {
                        self.acknowledge_control().await?;
                    }
                    if !accepted {
                        continue;
                    }
                    match message_type {
                        Some(MSG_HELLO) | None => {}
                        Some(MSG_STOP_CCN) => bail!("L2TP server closed the control tunnel"),
                        Some(MSG_CDN) => bail!("L2TP server closed the PPP session"),
                        Some(other) => debug!(
                            message_type = other,
                            "ignoring acknowledged L2TP control message"
                        ),
                    }
                }
            }
        }
    }

    pub async fn shutdown(&mut self) {
        if self.remote_session_id != 0 {
            let _ = self
                .send_control_once(
                    MSG_CDN,
                    self.remote_tunnel_id,
                    self.remote_session_id,
                    vec![
                        Avp::bytes(AVP_RESULT_CODE, 1u16.to_be_bytes()),
                        Avp::u16(AVP_ASSIGNED_SESSION_ID, self.local_session_id),
                    ],
                )
                .await;
        }
        if self.remote_tunnel_id != 0 {
            let _ = self
                .send_control_once(
                    MSG_STOP_CCN,
                    self.remote_tunnel_id,
                    0,
                    vec![
                        Avp::bytes(AVP_RESULT_CODE, 1u16.to_be_bytes()),
                        Avp::u16(AVP_ASSIGNED_TUNNEL_ID, self.local_tunnel_id),
                    ],
                )
                .await;
        }
    }

    async fn exchange(
        &mut self,
        request: ExchangeRequest,
        base_timeout: Duration,
        retries: u32,
    ) -> Result<ControlFrame> {
        let ExchangeRequest {
            message_type,
            tunnel_id,
            session_id,
            avps,
            expected_message,
        } = request;
        let ns = self.control_tx_ns;
        self.control_tx_ns = self.control_tx_ns.wrapping_add(1);

        for attempt in 0..=retries {
            let packet = encode_control_packet(
                tunnel_id,
                session_id,
                ns,
                self.control_rx_next,
                message_type,
                &avps,
            )?;
            self.socket
                .send(&packet)
                .await
                .with_context(|| format!("failed to send L2TP control message {message_type}"))?;
            debug!(message_type, ns, attempt, "sent L2TP control message");

            let multiplier = 1u32 << attempt.min(3);
            let deadline = Instant::now() + base_timeout.saturating_mul(multiplier);
            loop {
                let received = match tokio::time::timeout_at(deadline, self.receive_one()).await {
                    Ok(result) => result?,
                    Err(_) => break,
                };

                match received {
                    Packet::Data(frame) => {
                        if frame.tunnel_id == self.local_tunnel_id
                            && (frame.session_id == self.local_session_id
                                || self.remote_session_id == 0)
                        {
                            self.pending_data.push_back(frame);
                        }
                    }
                    Packet::Control(frame) => {
                        if !self.control_destination_matches(&frame) {
                            debug!(
                                tunnel_id = frame.tunnel_id,
                                session_id = frame.session_id,
                                "ignoring L2TP control message addressed to another tunnel"
                            );
                            continue;
                        }
                        frame.validate_mandatory_avps()?;
                        let acked = frame.nr == ns.wrapping_add(1);
                        let incoming_type = frame.message_type()?;
                        trace!(
                            message_type = ?incoming_type,
                            ns = frame.ns,
                            nr = frame.nr,
                            "received L2TP control message during negotiation");
                        let accepted = self.accept_control(&frame, incoming_type.is_some());

                        // RFC 2661 states that a ZLB does not consume a sequence number; only its
                        // Nr is processed.
                        if self.remote_tunnel_id != 0 && incoming_type.is_some() {
                            self.acknowledge_control().await?;
                        }
                        if !accepted {
                            continue;
                        }

                        match incoming_type {
                            Some(MSG_STOP_CCN) => {
                                bail!(
                                    "server closed the L2TP tunnel during negotiation: {}",
                                    result_text(&frame)
                                );
                            }
                            Some(MSG_CDN) => {
                                bail!(
                                    "server closed the L2TP session during negotiation: {}",
                                    result_text(&frame)
                                );
                            }
                            _ => {}
                        }

                        if expected_message == incoming_type && acked {
                            return Ok(frame);
                        }
                        if expected_message.is_none() && acked {
                            return Ok(frame);
                        }
                    }
                }
            }

            if attempt < retries {
                debug!(
                    message_type,
                    ns, attempt, "L2TP control message timed out, retransmitting"
                );
            }
        }

        bail!(
            "L2TP control message {message_type} not acknowledged after {} attempts",
            retries + 1
        )
    }

    async fn send_control_once(
        &mut self,
        message_type: u16,
        tunnel_id: u16,
        session_id: u16,
        avps: Vec<Avp>,
    ) -> Result<()> {
        let ns = self.control_tx_ns;
        self.control_tx_ns = self.control_tx_ns.wrapping_add(1);
        let packet = encode_control_packet(
            tunnel_id,
            session_id,
            ns,
            self.control_rx_next,
            message_type,
            &avps,
        )?;
        self.socket.send(&packet).await?;
        Ok(())
    }

    async fn acknowledge_control(&self) -> Result<()> {
        if self.remote_tunnel_id == 0 {
            return Ok(());
        }
        let packet = encode_zlb(
            self.remote_tunnel_id,
            self.control_tx_ns,
            self.control_rx_next,
        );
        self.socket
            .send(&packet)
            .await
            .context("failed to send L2TP ZLB acknowledgement")?;
        Ok(())
    }

    fn accept_control(&mut self, frame: &ControlFrame, consumes_sequence: bool) -> bool {
        if !consumes_sequence {
            return true;
        }
        if frame.ns != self.control_rx_next {
            debug!(
                ns = frame.ns,
                expected = self.control_rx_next,
                "received duplicate or out-of-order L2TP control message"
            );
            return false;
        }
        self.control_rx_next = self.control_rx_next.wrapping_add(1);
        true
    }

    fn validate_control_destination(&self, frame: &ControlFrame) -> Result<()> {
        if frame.tunnel_id != self.local_tunnel_id {
            bail!(
                "L2TP control message Tunnel ID mismatch: got {}, expected {}",
                frame.tunnel_id,
                self.local_tunnel_id
            );
        }
        Ok(())
    }

    fn control_destination_matches(&self, frame: &ControlFrame) -> bool {
        control_destination_matches(
            self.local_tunnel_id,
            self.local_session_id,
            frame.tunnel_id,
            frame.session_id,
        )
    }

    async fn receive_one(&mut self) -> Result<Packet> {
        let size = self
            .socket
            .recv(&mut self.receive_buffer)
            .await
            .context("failed to receive L2TP UDP datagram")?;
        parse_packet(&self.receive_buffer[..size])
    }
}

fn random_nonzero_u16() -> u16 {
    loop {
        let value = random();
        if value != 0 {
            return value;
        }
    }
}

fn supported_standard_avp(attribute: u16) -> bool {
    matches!(
        attribute,
        AVP_MESSAGE_TYPE
            | AVP_RESULT_CODE
            | AVP_PROTOCOL_VERSION
            | AVP_FRAMING_CAPABILITIES
            | AVP_BEARER_CAPABILITIES
            | AVP_HOST_NAME
            | AVP_VENDOR_NAME
            | AVP_ASSIGNED_TUNNEL_ID
            | AVP_RECEIVE_WINDOW_SIZE
            | AVP_CHALLENGE
            | AVP_ASSIGNED_SESSION_ID
            | AVP_CALL_SERIAL_NUMBER
            | AVP_BEARER_TYPE
            | AVP_FRAMING_TYPE
            | AVP_TX_CONNECT_SPEED
    )
}

/// Uses half of the u16 sequence space to tell forward from backward, which still holds across the
/// 65535→0 wrap.
fn classify_data_sequence(expected: u16, received: u16) -> DataSequence {
    match received.wrapping_sub(expected) {
        0 => DataSequence::Expected,
        distance @ 1..=0x7fff => DataSequence::Ahead { missing: distance },
        _ => DataSequence::DuplicateOrLate,
    }
}

fn control_destination_matches(
    local_tunnel_id: u16,
    local_session_id: u16,
    tunnel_id: u16,
    session_id: u16,
) -> bool {
    tunnel_id == local_tunnel_id && (session_id == 0 || session_id == local_session_id)
}

fn encode_control_packet(
    tunnel_id: u16,
    session_id: u16,
    ns: u16,
    nr: u16,
    message_type: u16,
    avps: &[Avp],
) -> Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(128);
    packet.extend_from_slice(&CONTROL_FLAGS.to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&tunnel_id.to_be_bytes());
    packet.extend_from_slice(&session_id.to_be_bytes());
    packet.extend_from_slice(&ns.to_be_bytes());
    packet.extend_from_slice(&nr.to_be_bytes());
    Avp::u16(AVP_MESSAGE_TYPE, message_type).encode(&mut packet)?;
    for avp in avps {
        avp.encode(&mut packet)?;
    }
    let length: u16 = packet
        .len()
        .try_into()
        .context("L2TP control message exceeds 65535 bytes")?;
    packet[2..4].copy_from_slice(&length.to_be_bytes());
    Ok(packet)
}

fn encode_zlb(tunnel_id: u16, ns: u16, nr: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(12);
    packet.extend_from_slice(&CONTROL_FLAGS.to_be_bytes());
    packet.extend_from_slice(&12u16.to_be_bytes());
    packet.extend_from_slice(&tunnel_id.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&ns.to_be_bytes());
    packet.extend_from_slice(&nr.to_be_bytes());
    packet
}

fn parse_packet(packet: &[u8]) -> Result<Packet> {
    if packet.len() < 6 {
        bail!("L2TP datagram is shorter than the minimum header");
    }
    let flags = read_u16(packet, 0)?;
    if flags & 0x000f != VERSION_2 {
        bail!("received a non-L2TPv2 datagram");
    }

    let is_control = flags & FLAG_TYPE != 0;
    let has_length = flags & FLAG_LENGTH != 0;
    let has_sequence = flags & FLAG_SEQUENCE != 0;
    let has_offset = flags & FLAG_OFFSET != 0;
    if is_control && (!has_length || !has_sequence || has_offset) {
        bail!("invalid L2TP control message header flags");
    }

    let mut cursor = 2usize;
    let declared_length = if has_length {
        let length = read_u16(packet, cursor)? as usize;
        cursor += 2;
        if length > packet.len() || length < 6 {
            bail!("invalid L2TP Length field");
        }
        length
    } else {
        packet.len()
    };

    let tunnel_id = read_u16(packet, cursor)?;
    let session_id = read_u16(packet, cursor + 2)?;
    cursor += 4;

    let (ns, nr) = if has_sequence {
        let ns = read_u16(packet, cursor)?;
        let nr = read_u16(packet, cursor + 2)?;
        cursor += 4;
        (Some(ns), Some(nr))
    } else {
        (None, None)
    };

    if has_offset {
        let offset = read_u16(packet, cursor)? as usize;
        cursor = cursor
            .checked_add(2 + offset)
            .context("L2TP Offset overflow")?;
    }
    if cursor > declared_length {
        bail!("L2TP header exceeds the Length field");
    }

    if is_control {
        let mut avps = Vec::new();
        while cursor < declared_length {
            if declared_length - cursor < 6 {
                bail!("incomplete L2TP AVP header");
            }
            let flags_length = read_u16(packet, cursor)?;
            let length = (flags_length & 0x03ff) as usize;
            if length < 6 || cursor + length > declared_length {
                bail!("invalid L2TP AVP length");
            }
            avps.push(Avp {
                mandatory: flags_length & 0x8000 != 0,
                hidden: flags_length & 0x4000 != 0,
                vendor_id: read_u16(packet, cursor + 2)?,
                attribute: read_u16(packet, cursor + 4)?,
                value: packet[cursor + 6..cursor + length].to_vec(),
            });
            cursor += length;
        }
        Ok(Packet::Control(ControlFrame {
            tunnel_id,
            session_id,
            ns: ns.expect("control messages have the Sequence flag verified"),
            nr: nr.expect("control messages have the Sequence flag verified"),
            avps,
        }))
    } else {
        Ok(Packet::Data(DataFrame {
            tunnel_id,
            session_id,
            ns,
            nr,
            payload: packet[cursor..declared_length].to_vec(),
        }))
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow!("truncated L2TP field"))?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn result_text(frame: &ControlFrame) -> String {
    let Some(avp) = frame.avp(AVP_RESULT_CODE) else {
        return "no Result Code".to_owned();
    };
    if avp.value.len() < 2 {
        return "invalid Result Code length".to_owned();
    }
    let result = u16::from_be_bytes([avp.value[0], avp.value[1]]);
    let message_start = if avp.value.len() >= 4 { 4 } else { 2 };
    let message = String::from_utf8_lossy(&avp.value[message_start..]);
    if message.is_empty() {
        format!("result code {result}")
    } else {
        format!("result code {result}: {message}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_message_round_trips() {
        let encoded = encode_control_packet(
            42,
            7,
            3,
            9,
            MSG_ICCN,
            &[Avp::u32(AVP_TX_CONNECT_SPEED, 100_000_000)],
        )
        .unwrap();
        let Packet::Control(parsed) = parse_packet(&encoded).unwrap() else {
            panic!("expected a control message");
        };
        assert_eq!(parsed.tunnel_id, 42);
        assert_eq!(parsed.session_id, 7);
        assert_eq!(parsed.ns, 3);
        assert_eq!(parsed.nr, 9);
        assert_eq!(parsed.message_type().unwrap(), Some(MSG_ICCN));
        assert_eq!(parsed.avp(AVP_TX_CONNECT_SPEED).unwrap().value.len(), 4);
    }

    #[test]
    fn parses_data_message_without_sequence() {
        let packet = [0x00, 0x02, 0x00, 0x2a, 0x00, 0x07, 0xff, 0x03, 0xc0, 0x21];
        let Packet::Data(parsed) = parse_packet(&packet).unwrap() else {
            panic!("expected a data message");
        };
        assert_eq!(parsed.tunnel_id, 42);
        assert_eq!(parsed.session_id, 7);
        assert_eq!(parsed.payload, [0xff, 0x03, 0xc0, 0x21]);
    }

    #[test]
    fn zlb_has_no_message_type() {
        let Packet::Control(parsed) = parse_packet(&encode_zlb(42, 3, 9)).unwrap() else {
            panic!("expected a control message");
        };
        assert_eq!(parsed.message_type().unwrap(), None);
        assert_eq!(parsed.ns, 3);
        assert_eq!(parsed.nr, 9);
    }

    #[test]
    fn rejects_truncated_avp() {
        let packet = [
            0xc8, 0x02, 0x00, 0x12, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x08,
            0x00, 0x00, 0x00, 0x00,
        ];
        assert!(parse_packet(&packet).is_err());
    }

    #[test]
    fn control_message_must_target_current_tunnel_or_session() {
        assert!(control_destination_matches(42, 7, 42, 0));
        assert!(control_destination_matches(42, 7, 42, 7));
        assert!(!control_destination_matches(42, 7, 41, 0));
        assert!(!control_destination_matches(42, 7, 42, 8));
    }

    #[test]
    fn data_sequence_gap_does_not_stall_receiving() {
        assert_eq!(classify_data_sequence(10, 10), DataSequence::Expected);
        assert_eq!(
            classify_data_sequence(10, 12),
            DataSequence::Ahead { missing: 2 }
        );
        assert_eq!(
            classify_data_sequence(12, 11),
            DataSequence::DuplicateOrLate
        );
        assert_eq!(
            classify_data_sequence(u16::MAX, 0),
            DataSequence::Ahead { missing: 1 }
        );
    }

    #[test]
    fn rejects_unknown_mandatory_avp_but_allows_unknown_optional_avp() {
        let mut frame = ControlFrame {
            tunnel_id: 42,
            session_id: 0,
            ns: 0,
            nr: 0,
            avps: vec![Avp {
                mandatory: true,
                hidden: false,
                vendor_id: 0,
                attribute: 999,
                value: vec![],
            }],
        };
        assert!(frame.validate_mandatory_avps().is_err());

        frame.avps[0].mandatory = false;
        assert!(frame.validate_mandatory_avps().is_ok());
    }

    #[test]
    fn accepts_standard_mandatory_bearer_capabilities_avp() {
        let frame = ControlFrame {
            tunnel_id: 42,
            session_id: 0,
            ns: 0,
            nr: 0,
            avps: vec![Avp::u32(AVP_BEARER_CAPABILITIES, 3)],
        };

        frame.validate_mandatory_avps().unwrap();
        assert_eq!(
            frame
                .optional_u32(AVP_BEARER_CAPABILITIES, "Bearer Capabilities")
                .unwrap(),
            Some(3)
        );
    }

    #[test]
    fn rejects_bearer_capabilities_with_wrong_length() {
        let frame = ControlFrame {
            tunnel_id: 42,
            session_id: 0,
            ns: 0,
            nr: 0,
            avps: vec![Avp::bytes(AVP_BEARER_CAPABILITIES, [0, 3])],
        };

        assert!(
            frame
                .optional_u32(AVP_BEARER_CAPABILITIES, "Bearer Capabilities")
                .is_err()
        );
    }
}
