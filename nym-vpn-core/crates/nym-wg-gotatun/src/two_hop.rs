// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! In-process link between the two WireGuard devices of a two-hop tunnel.
//!
//! Stacked through the kernel, every packet of the exit device crosses the
//! entry tunnel interface as a UDP datagram: a socket send, a route lookup
//! and a TUN read on the way out, a TUN write and a socket receive on the
//! way in. Here the exit device hands its datagrams to the entry device over
//! gotatun's channel transport instead, already wrapped in the IP and UDP
//! headers the entry gateway expects.
//!
//! The entry tunnel interface stays: the daemon reaches the entry gateway's
//! in-tunnel services through it. So the entry device's IP side is split.
//! Datagrams from the exit endpoint go to the exit device, everything else
//! goes to the interface, and packets from both are sent out.
//!
//! gotatun's channel ends panic when the other end is gone: a sender without
//! its receiver, a receiver without its senders. Every end here therefore
//! holds the whole link, so no order of stopping or dropping the two devices
//! can leave one end without the other. A device that outlives its partner
//! sees a link that is silent, not one that is closed.

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{
        IpRecv, IpSend, MtuWatcher,
        channel::{TunChannelRx, TunChannelTx, new_udp_tun_channel},
        tun_async_device::TunDevice,
    },
    udp::{
        UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams,
        channel::{UdpChannelFactory, UdpChannelTx, UdpChannelV4Rx, UdpChannelV6Rx},
    },
};
use tokio::sync::{Mutex, OwnedMutexGuard};

/// Packets buffered in each direction between the two devices.
const LINK_CAPACITY: usize = 512;

const IP_PROTOCOL_UDP: u8 = 17;

/// What the exit device's datagrams look like inside the entry tunnel.
#[derive(Clone, Copy, Debug)]
pub struct TwoHopLink {
    /// Our IPv4 address inside the entry tunnel.
    pub source_v4: Ipv4Addr,
    /// Our IPv6 address inside the entry tunnel.
    pub source_v6: Ipv6Addr,
    /// The exit gateway's WireGuard endpoint, reached through the entry tunnel.
    pub exit_endpoint: SocketAddr,
}

/// Both directions of the link. Whoever holds this keeps every sender and
/// every receiver alive.
struct Link {
    /// Senders towards the exit device.
    entry_tx: Arc<Mutex<TunChannelTx>>,
    /// Receiver for what the exit device sends.
    entry_rx: Arc<Mutex<TunChannelRx>>,
    /// The exit device's senders and receivers.
    exit_udp: Mutex<UdpChannelFactory>,
}

impl Link {
    fn new(params: TwoHopLink, entry_mtu: MtuWatcher) -> Arc<Self> {
        let (channel_tx, channel_rx, udp) =
            new_udp_tun_channel(LINK_CAPACITY, params.source_v4, params.source_v6, entry_mtu);
        Arc::new(Self {
            entry_tx: Arc::new(Mutex::new(channel_tx)),
            entry_rx: Arc::new(Mutex::new(channel_rx)),
            exit_udp: Mutex::new(udp),
        })
    }
}

/// Builds the entry device's IP side and the exit device's UDP side.
pub(crate) async fn split(
    params: TwoHopLink,
    entry_tun: TunDevice,
) -> (EntryIpTx, EntryIpRx, ExitUdpFactory) {
    let link = Link::new(params, entry_tun.mtu());

    let entry_tx = EntryIpTx {
        channel: Arc::clone(&link.entry_tx).lock_owned().await,
        tun: entry_tun.clone(),
        exit_endpoint: params.exit_endpoint,
        _link: Arc::clone(&link),
    };
    let entry_rx = EntryIpRx {
        channel: Arc::clone(&link.entry_rx).lock_owned().await,
        tun: entry_tun,
        channel_pool: PacketBufPool::new(1),
        _link: Arc::clone(&link),
    };
    let exit_udp = ExitUdpFactory { link };

    (entry_tx, entry_rx, exit_udp)
}

/// Where the entry device delivers the packets it decrypted.
pub(crate) struct EntryIpTx {
    channel: OwnedMutexGuard<TunChannelTx>,
    tun: TunDevice,
    exit_endpoint: SocketAddr,
    _link: Arc<Link>,
}

impl IpSend for EntryIpTx {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        if is_udp_from(&packet, self.exit_endpoint) {
            self.channel.send(packet).await
        } else {
            self.tun.send(packet).await
        }
    }
}

/// Where the entry device takes the packets it encrypts.
pub(crate) struct EntryIpRx {
    channel: OwnedMutexGuard<TunChannelRx>,
    tun: TunDevice,
    /// The channel hands over ready packets and ignores the pool it is given.
    channel_pool: PacketBufPool,
    _link: Arc<Link>,
}

impl IpRecv for EntryIpRx {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        tokio::select! {
            packets = recv_from(&mut *self.channel, &mut self.channel_pool) => {
                packets.map(OneOf::Channel)
            }
            packets = recv_from(&mut self.tun, pool) => packets.map(OneOf::Tun),
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.tun.mtu()
    }
}

/// `IpRecv::recv` through the trait, which promises a `Send` iterator.
async fn recv_from<'a, R: IpRecv>(
    source: &'a mut R,
    pool: &mut PacketBufPool,
) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
    source.recv(pool).await
}

enum OneOf<C, T> {
    Channel(C),
    Tun(T),
}

impl<C, T> Iterator for OneOf<C, T>
where
    C: Iterator<Item = Packet<Ip>>,
    T: Iterator<Item = Packet<Ip>>,
{
    type Item = Packet<Ip>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Channel(packets) => packets.next(),
            Self::Tun(packets) => packets.next(),
        }
    }
}

/// The exit device's UDP transport: datagrams to and from the entry device.
pub(crate) struct ExitUdpFactory {
    link: Arc<Link>,
}

impl UdpTransportFactory for ExitUdpFactory {
    type SendV4 = ExitUdp<UdpChannelTx>;
    type SendV6 = ExitUdp<UdpChannelTx>;
    type RecvV4 = ExitUdp<UdpChannelV4Rx>;
    type RecvV6 = ExitUdp<UdpChannelV6Rx>;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<((Self::SendV4, Self::RecvV4), (Self::SendV6, Self::RecvV6))> {
        let ((tx_v4, rx_v4), (tx_v6, rx_v6)) =
            self.link.exit_udp.lock().await.bind(params).await?;
        Ok((
            (self.keep(tx_v4), self.keep(rx_v4)),
            (self.keep(tx_v6), self.keep(rx_v6)),
        ))
    }
}

impl ExitUdpFactory {
    fn keep<T>(&self, inner: T) -> ExitUdp<T> {
        ExitUdp {
            inner,
            _link: Arc::clone(&self.link),
        }
    }
}

/// One of gotatun's channel ends on the exit device, holding the link.
#[derive(Clone)]
pub(crate) struct ExitUdp<T> {
    inner: T,
    _link: Arc<Link>,
}

impl UdpSend for ExitUdp<UdpChannelTx> {
    type SendManyBuf = <UdpChannelTx as UdpSend>::SendManyBuf;

    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        self.inner.send_to(packet, destination).await
    }
}

impl UdpRecv for ExitUdp<UdpChannelV4Rx> {
    type RecvManyBuf = <UdpChannelV4Rx as UdpRecv>::RecvManyBuf;

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        self.inner.recv_from(pool).await
    }
}

impl UdpRecv for ExitUdp<UdpChannelV6Rx> {
    type RecvManyBuf = <UdpChannelV6Rx as UdpRecv>::RecvManyBuf;

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        self.inner.recv_from(pool).await
    }
}

/// Whether `packet` is a UDP datagram sent by `endpoint`.
///
/// A later fragment has no UDP header to read the port from; it is matched
/// on the address alone and reassembled on the channel side.
fn is_udp_from(packet: &Ip, endpoint: SocketAddr) -> bool {
    let first_byte = packet.header.into_bits();
    // Everything after the first byte, so offsets below are one less than
    // their position in the header.
    let rest = &packet.rest;

    match (first_byte >> 4, endpoint) {
        (4, SocketAddr::V4(endpoint)) => {
            let header_len = usize::from(first_byte & 0x0f) * 4;
            if header_len < 20 || rest.len() < header_len + 1 {
                return false;
            }
            if rest[8] != IP_PROTOCOL_UDP || rest[11..15] != endpoint.ip().octets() {
                return false;
            }
            let fragment_offset = u16::from_be_bytes([rest[5], rest[6]]) & 0x1fff;
            fragment_offset != 0
                || rest[header_len - 1..header_len + 1] == endpoint.port().to_be_bytes()
        }
        (6, SocketAddr::V6(endpoint)) => {
            rest.len() >= 41
                && rest[5] == IP_PROTOCOL_UDP
                && rest[7..23] == endpoint.ip().octets()
                && rest[39..41] == endpoint.port().to_be_bytes()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use bytes::BytesMut;
    use gotatun::packet::{Ip, Packet};

    use std::{sync::Arc, time::Duration};

    use gotatun::{
        packet::PacketBufPool,
        tun::{IpRecv, IpSend, MtuWatcher},
        udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams},
    };

    use super::{ExitUdpFactory, Link, TwoHopLink, is_udp_from};

    const EXIT_V4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
    const EXIT_PORT: u16 = 51822;

    fn ipv4(protocol: u8, source: Ipv4Addr, source_port: u16, fragment: u16) -> Packet<Ip> {
        let mut bytes = vec![0u8; 28];
        bytes[0] = 0x45;
        bytes[3] = 28;
        bytes[6..8].copy_from_slice(&fragment.to_be_bytes());
        bytes[9] = protocol;
        bytes[12..16].copy_from_slice(&source.octets());
        bytes[16..20].copy_from_slice(&[10, 1, 0, 2]);
        bytes[20..22].copy_from_slice(&source_port.to_be_bytes());
        Packet::from_bytes(BytesMut::from(bytes.as_slice()))
            .try_into_ip()
            .unwrap()
    }

    fn ipv6(next_header: u8, source: Ipv6Addr, source_port: u16) -> Packet<Ip> {
        let mut bytes = vec![0u8; 48];
        bytes[0] = 0x60;
        bytes[5] = 8;
        bytes[6] = next_header;
        bytes[8..24].copy_from_slice(&source.octets());
        bytes[40..42].copy_from_slice(&source_port.to_be_bytes());
        Packet::from_bytes(BytesMut::from(bytes.as_slice()))
            .try_into_ip()
            .unwrap()
    }

    fn exit() -> SocketAddr {
        SocketAddr::from((EXIT_V4, EXIT_PORT))
    }

    fn link() -> Arc<Link> {
        Link::new(
            TwoHopLink {
                source_v4: Ipv4Addr::new(10, 1, 0, 2),
                source_v6: Ipv6Addr::LOCALHOST,
                exit_endpoint: exit(),
            },
            MtuWatcher::new(1420),
        )
    }

    fn bind_params() -> UdpTransportFactoryParams {
        UdpTransportFactoryParams {
            addr_v4: Ipv4Addr::UNSPECIFIED,
            addr_v6: Ipv6Addr::UNSPECIFIED,
            port: 0,
            #[cfg(target_os = "linux")]
            fwmark: None,
        }
    }

    /// The exit device keeps receiving after the entry device is gone: its
    /// receiver must wait, where gotatun's own would panic.
    #[tokio::test]
    async fn exit_outlives_the_entry_device() {
        let link = link();
        let mut exit_udp = ExitUdpFactory {
            link: Arc::clone(&link),
        };
        let ((exit_tx, mut exit_rx), _v6) = exit_udp.bind(&bind_params()).await.unwrap();

        // The entry device held these two ends and dropped them when stopped.
        let entry_tx = Arc::clone(&link.entry_tx).lock_owned().await;
        let entry_rx = Arc::clone(&link.entry_rx).lock_owned().await;
        drop((entry_tx, entry_rx, link));

        let mut pool = PacketBufPool::new(1);
        let received =
            tokio::time::timeout(Duration::from_millis(50), exit_rx.recv_from(&mut pool)).await;
        assert!(received.is_err(), "receive should wait, not finish");

        let datagram = gotatun::packet::Packet::from_bytes(BytesMut::from(&[0u8; 32][..]));
        exit_tx.send_to(datagram, exit()).await.unwrap();
    }

    /// The entry device keeps delivering after the exit device is gone: its
    /// send must succeed, where gotatun's own would panic.
    #[tokio::test]
    async fn entry_outlives_the_exit_device() {
        let link = link();
        let mut exit_udp = ExitUdpFactory {
            link: Arc::clone(&link),
        };
        // The entry device's two ends; like them, the test holds the link.
        let mut entry_tx = Arc::clone(&link.entry_tx).lock_owned().await;
        let mut entry_rx = Arc::clone(&link.entry_rx).lock_owned().await;

        // A well-formed datagram, as the exit device would send it.
        let (exit_ends, _v6) = exit_udp.bind(&bind_params()).await.unwrap();
        let datagram = gotatun::packet::Packet::from_bytes(BytesMut::from(&[0u8; 32][..]));
        exit_ends.0.send_to(datagram, exit()).await.unwrap();
        let mut pool = PacketBufPool::new(1);
        let packet = entry_rx.recv(&mut pool).await.unwrap().next().unwrap();

        // The exit device is stopped and dropped.
        drop((exit_ends, _v6, exit_udp));

        entry_tx.send(packet).await.unwrap();
        let waiting =
            tokio::time::timeout(Duration::from_millis(50), entry_rx.recv(&mut pool)).await;
        assert!(waiting.is_err(), "receive should wait, not fail");
        drop(link);
    }

    #[test]
    fn exit_datagram_goes_to_the_exit_device() {
        assert!(is_udp_from(&ipv4(17, EXIT_V4, EXIT_PORT, 0), exit()));
    }

    #[test]
    fn other_traffic_stays_on_the_interface() {
        let metadata = Ipv4Addr::new(10, 1, 0, 1);
        // Another host, another port, another protocol.
        assert!(!is_udp_from(&ipv4(17, metadata, EXIT_PORT, 0), exit()));
        assert!(!is_udp_from(&ipv4(17, EXIT_V4, 443, 0), exit()));
        assert!(!is_udp_from(&ipv4(6, EXIT_V4, EXIT_PORT, 0), exit()));
        assert!(!is_udp_from(&ipv4(1, EXIT_V4, 0, 0), exit()));
    }

    #[test]
    fn later_fragment_is_matched_on_the_address() {
        // Offset 185, no UDP header: the bytes where a port would be differ.
        assert!(is_udp_from(&ipv4(17, EXIT_V4, 1, 185), exit()));
        assert!(!is_udp_from(
            &ipv4(17, Ipv4Addr::new(10, 1, 0, 1), 1, 185),
            exit()
        ));
    }

    #[test]
    fn first_fragment_still_needs_the_port() {
        const MORE_FRAGMENTS: u16 = 0x2000;
        assert!(is_udp_from(
            &ipv4(17, EXIT_V4, EXIT_PORT, MORE_FRAGMENTS),
            exit()
        ));
        assert!(!is_udp_from(&ipv4(17, EXIT_V4, 443, MORE_FRAGMENTS), exit()));
    }

    #[test]
    fn ipv6_exit_datagram_is_matched() {
        let exit_v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7);
        let endpoint = SocketAddr::from((exit_v6, EXIT_PORT));
        assert!(is_udp_from(&ipv6(17, exit_v6, EXIT_PORT), endpoint));
        assert!(!is_udp_from(&ipv6(6, exit_v6, EXIT_PORT), endpoint));
        assert!(!is_udp_from(&ipv6(17, exit_v6, 443), endpoint));
        // An IPv4 endpoint never matches an IPv6 packet.
        assert!(!is_udp_from(&ipv6(17, exit_v6, EXIT_PORT), exit()));
    }
}
