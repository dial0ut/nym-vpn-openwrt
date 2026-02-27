// Copyright 2024 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! AmneziaWG obfuscation layer for gotatun's UDP transport.
//!
//! Wraps any [`UdpTransportFactory`] to apply AmneziaWG packet obfuscation:
//! - **H1-H4**: Header remapping — replaces the 4-byte LE message type field with custom values
//! - **S1/S2**: Padding — prepends random bytes to handshake init/response packets
//! - **Jc/Jmin/Jmax**: Junk packets — sends random UDP packets before handshake init

use std::{future::Future, io, net::SocketAddr, sync::Arc};

use bytes::BytesMut;
use gotatun::{
    packet::{Packet, PacketBufPool},
    udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams},
};
use rand::Rng;

use crate::amnezia::AmneziaConfig;

// Standard WireGuard message types (4-byte LE)
const WG_INIT: i32 = 1;
const WG_RESPONSE: i32 = 2;
const WG_COOKIE: i32 = 3;
const WG_DATA: i32 = 4;

// Standard WireGuard packet sizes (without padding)
const WG_INIT_SIZE: usize = 148;
const WG_RESPONSE_SIZE: usize = 92;
const WG_COOKIE_SIZE: usize = 64;
const WG_DATA_MIN_SIZE: usize = 32;

/// Resolved obfuscation parameters, derived from [`AmneziaConfig`].
///
/// `None` means passthrough (amnezia OFF / absent).
#[derive(Debug, Clone)]
struct AmneziaParams {
    h1: i32,
    h2: i32,
    h3: i32,
    h4: i32,
    s1: usize,
    s2: usize,
    jc: usize,
    jmin: usize,
    jmax: usize,
}

impl AmneziaParams {
    fn from_config(config: &AmneziaConfig) -> Option<Self> {
        if config.is_off() {
            return None;
        }
        Some(Self {
            h1: config.init_pkt_magic_header,
            h2: config.response_pkt_magic_header,
            h3: config.under_load_pkt_magic_header,
            h4: config.transport_pkt_magic_header,
            s1: config.init_pkt_junk_size as usize,
            s2: config.response_pkt_junk_size as usize,
            jc: config.junk_pkt_count as usize,
            jmin: config.junk_pkt_min_size as usize,
            jmax: config.junk_pkt_max_size as usize,
        })
    }
}

/// A [`UdpTransportFactory`] wrapper that applies AmneziaWG obfuscation.
///
/// When `params` is `None` (config is OFF or absent), all methods delegate
/// directly to the inner factory with zero overhead.
pub struct AmneziaUdpFactory<F: UdpTransportFactory> {
    inner: F,
    params: Option<Arc<AmneziaParams>>,
}

impl<F: UdpTransportFactory> AmneziaUdpFactory<F> {
    /// Create a new `AmneziaUdpFactory` wrapping the given inner factory.
    ///
    /// If `config` is `None` or represents the OFF config, the factory operates
    /// in passthrough mode with no packet modification.
    pub fn new(inner: F, config: Option<&AmneziaConfig>) -> Self {
        let params = config.and_then(AmneziaParams::from_config).map(Arc::new);

        if let Some(ref p) = params {
            tracing::info!(
                h1 = p.h1, h2 = p.h2, h3 = p.h3, h4 = p.h4,
                s1 = p.s1, s2 = p.s2, jc = p.jc, jmin = p.jmin, jmax = p.jmax,
                "AmneziaWG obfuscation enabled"
            );
        } else {
            tracing::debug!("AmneziaWG obfuscation disabled (passthrough mode)");
        }

        Self { inner, params }
    }
}

impl<F: UdpTransportFactory> UdpTransportFactory for AmneziaUdpFactory<F> {
    type SendV4 = AmneziaSend<F::SendV4>;
    type SendV6 = AmneziaSend<F::SendV6>;
    type RecvV4 = AmneziaRecv<F::RecvV4>;
    type RecvV6 = AmneziaRecv<F::RecvV6>;

    fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> impl Future<
        Output = io::Result<((Self::SendV4, Self::RecvV4), (Self::SendV6, Self::RecvV6))>,
    > + Send {
        let azwg = self.params.clone();
        let inner_fut = self.inner.bind(params);

        async move {
            let ((send_v4, recv_v4), (send_v6, recv_v6)) = inner_fut.await?;

            Ok((
                (
                    AmneziaSend::new(send_v4, azwg.clone()),
                    AmneziaRecv::new(recv_v4, azwg.clone()),
                ),
                (
                    AmneziaSend::new(send_v6, azwg.clone()),
                    AmneziaRecv::new(recv_v6, azwg),
                ),
            ))
        }
    }
}

/// Wraps a [`UdpSend`] to apply AmneziaWG obfuscation on outgoing packets.
#[derive(Clone)]
pub struct AmneziaSend<S: UdpSend> {
    inner: S,
    params: Option<Arc<AmneziaParams>>,
}

impl<S: UdpSend> AmneziaSend<S> {
    fn new(inner: S, params: Option<Arc<AmneziaParams>>) -> Self {
        Self { inner, params }
    }
}

impl<S: UdpSend> UdpSend for AmneziaSend<S> {
    type SendManyBuf = S::SendManyBuf;

    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        let Some(ref params) = self.params else {
            return self.inner.send_to(packet, destination).await;
        };

        let data: &[u8] = &packet;
        if data.len() < 4 {
            return self.inner.send_to(packet, destination).await;
        }

        let msg_type = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        match msg_type {
            WG_INIT => {
                // Send Jc junk packets before handshake init
                send_junk(&self.inner, params, destination).await?;
                // Remap header and optionally pad with S1
                let obfuscated = remap_and_pad(data, params.h1, params.s1);
                self.inner
                    .send_to(Packet::from_bytes(obfuscated), destination)
                    .await
            }
            WG_RESPONSE => {
                let obfuscated = remap_and_pad(data, params.h2, params.s2);
                self.inner
                    .send_to(Packet::from_bytes(obfuscated), destination)
                    .await
            }
            WG_COOKIE => {
                let obfuscated = remap_header(data, params.h3);
                self.inner
                    .send_to(Packet::from_bytes(obfuscated), destination)
                    .await
            }
            WG_DATA => {
                let obfuscated = remap_header(data, params.h4);
                self.inner
                    .send_to(Packet::from_bytes(obfuscated), destination)
                    .await
            }
            _ => {
                // Unknown message type — pass through unchanged
                self.inner.send_to(packet, destination).await
            }
        }
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        self.inner.max_number_of_packets_to_send()
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }

    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, mark: u32) -> io::Result<()> {
        self.inner.set_fwmark(mark)
    }
}

/// Wraps a [`UdpRecv`] to strip AmneziaWG obfuscation from incoming packets.
pub struct AmneziaRecv<R: UdpRecv> {
    inner: R,
    params: Option<Arc<AmneziaParams>>,
}

impl<R: UdpRecv> AmneziaRecv<R> {
    fn new(inner: R, params: Option<Arc<AmneziaParams>>) -> Self {
        Self { inner, params }
    }
}

impl<R: UdpRecv> UdpRecv for AmneziaRecv<R> {
    type RecvManyBuf = R::RecvManyBuf;

    async fn recv_from(
        &mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<(Packet, SocketAddr)> {
        let Some(ref params) = self.params else {
            return self.inner.recv_from(pool).await;
        };

        loop {
            let (packet, addr) = self.inner.recv_from(pool).await?;
            let data: &[u8] = &packet;

            if data.len() < 4 {
                // Too short to be a WG packet, discard
                continue;
            }

            let header = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);

            // Try to match cookie (H3) — fixed size 64
            if header == params.h3 && data.len() == WG_COOKIE_SIZE {
                let restored = remap_header(data, WG_COOKIE);
                return Ok((Packet::from_bytes(restored), addr));
            }

            // Try to match data (H4) — minimum size 32
            if header == params.h4 && data.len() >= WG_DATA_MIN_SIZE {
                let restored = remap_header(data, WG_DATA);
                return Ok((Packet::from_bytes(restored), addr));
            }

            // Try to match unpadded init (H1, S1==0) — exactly 148
            if params.s1 == 0 && header == params.h1 && data.len() == WG_INIT_SIZE {
                let restored = remap_header(data, WG_INIT);
                return Ok((Packet::from_bytes(restored), addr));
            }

            // Try to match unpadded response (H2, S2==0) — exactly 92
            if params.s2 == 0 && header == params.h2 && data.len() == WG_RESPONSE_SIZE {
                let restored = remap_header(data, WG_RESPONSE);
                return Ok((Packet::from_bytes(restored), addr));
            }

            // Try to match padded init (S1 > 0) — size == S1 + 148
            if params.s1 > 0 && data.len() == params.s1 + WG_INIT_SIZE {
                if data.len() >= params.s1 + 4 {
                    let inner_header = i32::from_le_bytes([
                        data[params.s1],
                        data[params.s1 + 1],
                        data[params.s1 + 2],
                        data[params.s1 + 3],
                    ]);
                    if inner_header == params.h1 {
                        let stripped = strip_padding_and_remap(data, params.s1, WG_INIT);
                        return Ok((Packet::from_bytes(stripped), addr));
                    }
                }
            }

            // Try to match padded response (S2 > 0) — size == S2 + 92
            if params.s2 > 0 && data.len() == params.s2 + WG_RESPONSE_SIZE {
                if data.len() >= params.s2 + 4 {
                    let inner_header = i32::from_le_bytes([
                        data[params.s2],
                        data[params.s2 + 1],
                        data[params.s2 + 2],
                        data[params.s2 + 3],
                    ]);
                    if inner_header == params.h2 {
                        let stripped = strip_padding_and_remap(data, params.s2, WG_RESPONSE);
                        return Ok((Packet::from_bytes(stripped), addr));
                    }
                }
            }

            // Doesn't match any known pattern — junk or unknown, discard and loop
            tracing::trace!(
                len = data.len(),
                header,
                "Discarding unrecognized packet (likely junk)"
            );
        }
    }

    fn enable_udp_gro(&self) -> io::Result<()> {
        self.inner.enable_udp_gro()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Remap the first 4 bytes of a packet to `new_header`, returning a new BytesMut.
fn remap_header(data: &[u8], new_header: i32) -> BytesMut {
    let mut buf = BytesMut::with_capacity(data.len());
    buf.extend_from_slice(&new_header.to_le_bytes());
    buf.extend_from_slice(&data[4..]);
    buf
}

/// Remap header and prepend `pad_size` random bytes.
fn remap_and_pad(data: &[u8], new_header: i32, pad_size: usize) -> BytesMut {
    let mut buf = BytesMut::with_capacity(pad_size + data.len());

    if pad_size > 0 {
        // Fill padding with random bytes
        let mut padding = vec![0u8; pad_size];
        rand::thread_rng().fill(&mut padding[..]);
        buf.extend_from_slice(&padding);
    }

    buf.extend_from_slice(&new_header.to_le_bytes());
    buf.extend_from_slice(&data[4..]);
    buf
}

/// Strip `pad_size` prefix bytes and remap the header to `new_header`.
fn strip_padding_and_remap(data: &[u8], pad_size: usize, new_header: i32) -> BytesMut {
    let inner = &data[pad_size..];
    let mut buf = BytesMut::with_capacity(inner.len());
    buf.extend_from_slice(&new_header.to_le_bytes());
    buf.extend_from_slice(&inner[4..]);
    buf
}

/// Generate junk packets eagerly (so the RNG doesn't live across awaits),
/// then send them.
async fn send_junk<S: UdpSend>(
    sender: &S,
    params: &AmneziaParams,
    destination: SocketAddr,
) -> io::Result<()> {
    if params.jc == 0 {
        return Ok(());
    }

    // Generate all junk data upfront so thread_rng() doesn't span an await
    let junk_packets: Vec<BytesMut> = {
        let mut rng = rand::thread_rng();
        (0..params.jc)
            .map(|_| {
                let size = if params.jmin >= params.jmax {
                    params.jmin
                } else {
                    rng.gen_range(params.jmin..=params.jmax)
                };
                let mut junk = vec![0u8; size];
                rng.fill(&mut junk[..]);
                BytesMut::from(&junk[..])
            })
            .collect()
    };

    for junk in junk_packets {
        sender
            .send_to(Packet::from_bytes(junk), destination)
            .await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify header remap round-trips correctly.
    #[test]
    fn header_remap_roundtrip() {
        // Simulate a WG init packet (type 1)
        let mut init_packet = vec![0u8; WG_INIT_SIZE];
        init_packet[..4].copy_from_slice(&WG_INIT.to_le_bytes());
        // Put some recognizable payload
        init_packet[4] = 0xAA;
        init_packet[5] = 0xBB;

        let custom_h1: i32 = 12345;

        // Remap 1 -> custom
        let remapped = remap_header(&init_packet, custom_h1);
        assert_eq!(remapped.len(), WG_INIT_SIZE);
        let header = i32::from_le_bytes([remapped[0], remapped[1], remapped[2], remapped[3]]);
        assert_eq!(header, custom_h1);
        assert_eq!(remapped[4], 0xAA);
        assert_eq!(remapped[5], 0xBB);

        // Remap custom -> 1
        let restored = remap_header(&remapped, WG_INIT);
        assert_eq!(restored.len(), WG_INIT_SIZE);
        let header = i32::from_le_bytes([restored[0], restored[1], restored[2], restored[3]]);
        assert_eq!(header, WG_INIT);
        assert_eq!(restored[4], 0xAA);
        assert_eq!(restored[5], 0xBB);
    }

    /// Verify S1 padding is correctly applied and stripped.
    #[test]
    fn padding_roundtrip() {
        let mut init_packet = vec![0u8; WG_INIT_SIZE];
        init_packet[..4].copy_from_slice(&WG_INIT.to_le_bytes());
        init_packet[10] = 0xCC;

        let custom_h1: i32 = 99999;
        let s1: usize = 50;

        // Pad and remap
        let padded = remap_and_pad(&init_packet, custom_h1, s1);
        assert_eq!(padded.len(), s1 + WG_INIT_SIZE);

        // Verify the header is at offset s1
        let header = i32::from_le_bytes([padded[s1], padded[s1 + 1], padded[s1 + 2], padded[s1 + 3]]);
        assert_eq!(header, custom_h1);

        // Strip and restore
        let restored = strip_padding_and_remap(&padded, s1, WG_INIT);
        assert_eq!(restored.len(), WG_INIT_SIZE);
        let header = i32::from_le_bytes([restored[0], restored[1], restored[2], restored[3]]);
        assert_eq!(header, WG_INIT);
        assert_eq!(restored[10], 0xCC);
    }

    /// Verify OFF config results in no params (passthrough).
    #[test]
    fn off_config_is_passthrough() {
        assert!(AmneziaParams::from_config(&AmneziaConfig::OFF).is_none());
    }

    /// Verify BASE config produces valid params with standard headers.
    #[test]
    fn base_config_params() {
        let params = AmneziaParams::from_config(&AmneziaConfig::BASE).unwrap();
        assert_eq!(params.h1, 1);
        assert_eq!(params.h2, 2);
        assert_eq!(params.h3, 3);
        assert_eq!(params.h4, 4);
        assert_eq!(params.s1, 0);
        assert_eq!(params.s2, 0);
        assert_eq!(params.jc, 4);
        assert!(params.jmin <= params.jmax);
    }

    /// Verify random config produces valid non-standard params.
    #[test]
    fn rand_config_params() {
        let mut rng = rand::thread_rng();
        let config = AmneziaConfig::rand(&mut rng);
        let params = AmneziaParams::from_config(&config).unwrap();

        // Random configs should have non-standard headers
        assert!(params.h1 >= 5);
        assert!(params.h2 >= 5);
        assert!(params.h3 >= 5);
        assert!(params.h4 >= 5);
        // All headers should be distinct
        assert_ne!(params.h1, params.h2);
        assert_ne!(params.h1, params.h3);
        assert_ne!(params.h1, params.h4);
    }

    /// Verify data packets (type 4) are correctly remapped.
    #[test]
    fn data_packet_remap() {
        let mut data_packet = vec![0u8; 100]; // arbitrary data packet size >= 32
        data_packet[..4].copy_from_slice(&WG_DATA.to_le_bytes());
        data_packet[20] = 0xFF;

        let custom_h4: i32 = 777;

        let remapped = remap_header(&data_packet, custom_h4);
        let header = i32::from_le_bytes([remapped[0], remapped[1], remapped[2], remapped[3]]);
        assert_eq!(header, custom_h4);
        assert_eq!(remapped[20], 0xFF);

        let restored = remap_header(&remapped, WG_DATA);
        let header = i32::from_le_bytes([restored[0], restored[1], restored[2], restored[3]]);
        assert_eq!(header, WG_DATA);
        assert_eq!(restored[20], 0xFF);
    }
}
