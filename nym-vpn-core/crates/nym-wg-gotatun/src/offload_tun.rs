// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Tunnel interface IO with the kernel's segmentation offload.
//!
//! A plain TUN device costs one system call per packet in each direction,
//! and every packet written walks the kernel's receive and forwarding path
//! by itself. A device opened with `IFF_VNET_HDR` exchanges frames that
//! start with a `virtio_net_hdr`, and with `TUNSETOFFLOAD` such a frame may
//! carry many TCP segments of one flow at once:
//!
//! * reading, the kernel hands over one large TCP packet and the size to cut
//!   it into ([`segment`]);
//! * writing, consecutive segments of a flow are merged into one large
//!   packet that the kernel forwards as a unit and cuts up again where it
//!   leaves ([`Coalescer`]).
//!
//! TCP is merged everywhere. UDP datagrams of one flow, as a QUIC download
//! sends them, are merged where the kernel can segment UDP (Linux 6.2).
//! Everything else passes one packet per frame.
//!
//! A device without `IFF_VNET_HDR` is read and written as before.

use std::{
    collections::HashMap,
    io,
    os::fd::{AsRawFd, BorrowedFd, IntoRawFd, RawFd},
    sync::{Arc, Weak},
    time::Duration,
};

use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
};
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tun::AbstractDevice;

/// The interface, readable and writable from the runtime it was opened on.
type Tun = AsyncFd<tun::Device>;

/// Size of the `virtio_net_hdr` in front of every frame.
const VNET_HDR_LEN: usize = 10;

/// Largest IP packet a frame can carry.
const MAX_PACKET: usize = 65535;

/// The packet's checksum covers the pseudo header only; whoever takes the
/// packet finishes it from `csum_start`.
const VNET_F_NEEDS_CSUM: u8 = 1;

const VNET_GSO_NONE: u8 = 0;
const VNET_GSO_TCPV4: u8 = 1;
const VNET_GSO_TCPV6: u8 = 4;
const VNET_GSO_UDP_L4: u8 = 5;
/// Set next to the type when the segments carry ECN.
const VNET_GSO_ECN: u8 = 0x80;

/// `TUNSETOFFLOAD` features: checksum offload and TCP segmentation.
const TUN_F_CSUM: libc::c_ulong = 0x01;
const TUN_F_TSO4: libc::c_ulong = 0x02;
const TUN_F_TSO6: libc::c_ulong = 0x04;
/// UDP segmentation, since Linux 6.2.
const TUN_F_USO4: libc::c_ulong = 0x20;
const TUN_F_USO6: libc::c_ulong = 0x40;

const IP_PROTOCOL_TCP: u8 = 6;
const IP_PROTOCOL_UDP: u8 = 17;

const TCP_FIN: u8 = 0x01;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
const TCP_CWR: u8 = 0x80;

/// Offset of the checksum in a TCP header.
const TCP_CHECKSUM: usize = 16;

const UDP_HEADER_LEN: usize = 8;
/// Offset of the checksum in a UDP header.
const UDP_CHECKSUM: usize = 6;
/// Most datagrams the kernel takes in one frame.
const UDP_MAX_SEGMENTS: usize = 64;

/// Packets taken off the queue and merged in one go.
const WRITE_BATCH: usize = 128;

/// Packets waiting for the writer before the device task is held back.
const WRITE_QUEUE: usize = 512;

/// How often the interface is asked for its MTU, as gotatun's own device does.
const MTU_POLL: Duration = Duration::from_secs(3);

/// Makes `config` create a device that can use segmentation offload.
pub fn enable_offload(config: &mut tun::Configuration) {
    config.platform_config(|platform| {
        platform.vnet_hdr(true);
    });
}

/// Splits `tun` into its write and read halves, served by the runtime this
/// is called on.
///
/// Segmentation offload is used when the device was created with
/// [`enable_offload`] and the kernel accepts it.
pub(crate) fn open(tun: tun::AsyncDevice) -> io::Result<(TunTx, TunRx)> {
    let tun = adopt(tun)?;
    let fd = tun.as_raw_fd();
    let vnet_hdr = has_vnet_hdr(fd)?;
    let offload = if vnet_hdr {
        set_offload(fd)
    } else {
        Offload::None
    };
    tracing::debug!("Tunnel interface segmentation offload: {offload:?}");

    let mtu = tun.get_ref().mtu().map_err(io::Error::other)?;
    let tun = Arc::new(tun);
    let (mtu, monitor) = watch_mtu(&tun, mtu);

    let tx = if vnet_hdr {
        let (tx, rx) = mpsc::channel(WRITE_QUEUE);
        let writer = AbortOnDrop(tokio::spawn(write_loop(Arc::downgrade(&tun), rx, offload)));
        TunTx::Framed {
            tx,
            _tun: Arc::clone(&tun),
            _writer: writer,
        }
    } else {
        TunTx::Plain(Arc::clone(&tun))
    };

    let rx = TunRx {
        frame: if vnet_hdr {
            vec![0; VNET_HDR_LEN + MAX_PACKET]
        } else {
            Vec::new()
        },
        tun,
        vnet_hdr,
        ready: Vec::new(),
        mtu,
        _monitor: monitor,
    };

    Ok((tx, rx))
}

/// Moves the device from the runtime it was created on to this one, so
/// that its readiness is watched by the thread that reads and writes it.
fn adopt(tun: tun::AsyncDevice) -> io::Result<Tun> {
    let name = tun.tun_name().map_err(io::Error::other)?;
    // SAFETY: the descriptor is open for as long as `tun` is borrowed here.
    let fd = unsafe { BorrowedFd::borrow_raw(tun.as_raw_fd()) }.try_clone_to_owned()?;
    // The copy keeps the interface; the original leaves its runtime.
    drop(tun);

    let mut config = tun::Configuration::default();
    config
        .tun_name(name)
        .raw_fd(fd.into_raw_fd())
        .close_fd_on_drop(true);
    let device = tun::create(&config).map_err(io::Error::other)?;
    device.set_nonblock()?;
    // SAFETY: `device` owns its descriptor and keeps it open, unchanged,
    // for as long as the `AsyncFd` owns `device`.
    Ok(unsafe { AsyncFd::register(device) }?)
}

async fn read(tun: &Tun, buf: &mut [u8]) -> io::Result<usize> {
    tun.async_io(Interest::READABLE, |device| {
        // SAFETY: `buf` is valid for writes of its length.
        let len = unsafe { libc::read(device.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if len < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(len as usize)
        }
    })
    .await
}

async fn write(tun: &Tun, buf: &[u8]) -> io::Result<()> {
    tun.async_io(Interest::WRITABLE, |device| {
        // SAFETY: `buf` is valid for reads of its length.
        let len = unsafe { libc::write(device.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
        if len < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    })
    .await
}

fn has_vnet_hdr(fd: RawFd) -> io::Result<bool> {
    // SAFETY: `ifreq` is plain data, valid when zeroed.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is an open TUN device and `request` outlives the call.
    if unsafe { libc::ioctl(fd, libc::TUNGETIFF, &mut request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `TUNGETIFF` fills in the flags member of the union.
    let flags = unsafe { request.ifr_ifru.ifru_flags };
    Ok(flags & libc::IFF_VNET_HDR as libc::c_short != 0)
}

/// What the kernel segments for us, and so what may be merged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Offload {
    None,
    Tcp,
    TcpAndUdp,
}

/// Turns on as much offload as the kernel has.
fn set_offload(fd: RawFd) -> Offload {
    let tcp = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
    let set = |features: libc::c_ulong| {
        // SAFETY: `fd` is an open TUN device; the argument is passed by value.
        let result = unsafe { libc::ioctl(fd, libc::TUNSETOFFLOAD, features) };
        result == 0
    };

    if set(tcp | TUN_F_USO4 | TUN_F_USO6) {
        Offload::TcpAndUdp
    } else if set(tcp) {
        Offload::Tcp
    } else {
        tracing::warn!(
            "Tunnel interface without segmentation offload: {}",
            io::Error::last_os_error()
        );
        Offload::None
    }
}

/// Follows the interface MTU until the device is closed.
fn watch_mtu(tun: &Arc<Tun>, mtu: u16) -> (MtuWatcher, AbortOnDrop) {
    let (tx, rx) = watch::channel(mtu);
    let tun = Arc::downgrade(tun);
    let monitor = tokio::spawn(async move {
        let mut mtu = mtu;
        loop {
            tokio::time::sleep(MTU_POLL).await;
            let Some(tun) = tun.upgrade() else { return };
            let Ok(current) = tun.get_ref().mtu() else {
                return;
            };
            if current != mtu {
                mtu = current;
                if tx.send(mtu).is_err() {
                    return;
                }
            }
        }
    });
    (rx.into(), AbortOnDrop(monitor))
}

pub(crate) struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The write half: packets for the tunnel interface.
pub(crate) enum TunTx {
    /// One packet per write, no frame header.
    Plain(Arc<Tun>),
    /// Packets are queued for [`write_loop`], which frames and merges them.
    Framed {
        tx: mpsc::Sender<Packet>,
        /// Keeps the interface up for as long as this half exists; the
        /// writer itself only borrows it while it writes.
        _tun: Arc<Tun>,
        _writer: AbortOnDrop,
    },
}

impl IpSend for TunTx {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        match self {
            Self::Plain(tun) => write(tun, &packet.into_bytes()).await,
            Self::Framed { tx, .. } => tx.send(packet.into_bytes()).await.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "tunnel interface writer stopped")
            }),
        }
    }
}

/// The read half: packets from the tunnel interface.
pub(crate) struct TunRx {
    tun: Arc<Tun>,
    vnet_hdr: bool,
    /// Where a frame is read into before it is cut up.
    frame: Vec<u8>,
    /// Packets of the last read, handed out by `recv`.
    ready: Vec<Packet<Ip>>,
    mtu: MtuWatcher,
    _monitor: AbortOnDrop,
}

impl IpRecv for TunRx {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        self.ready.clear();

        while self.ready.is_empty() {
            if self.vnet_hdr {
                let len = read(&self.tun, &mut self.frame).await?;
                if let Err(reason) = segment(&self.frame[..len], pool, &mut self.ready) {
                    tracing::trace!("Dropping a frame from the tunnel interface: {reason}");
                }
            } else {
                let mut packet = pool.get();
                let len = read(&self.tun, &mut packet).await?;
                packet.truncate(len);
                self.ready.push(
                    packet
                        .try_into_ip()
                        .map_err(|e| io::Error::other(e.to_string()))?,
                );
            }
        }

        Ok(self.ready.drain(..))
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
    }
}

/// Takes queued packets in batches, merges what can be merged and writes
/// the frames. Ends when the queue closes or the interface is gone.
async fn write_loop(tun: Weak<Tun>, mut rx: mpsc::Receiver<Packet>, offload: Offload) {
    let mut batch: Vec<Packet> = Vec::with_capacity(WRITE_BATCH);
    let mut coalescer = Coalescer {
        udp: offload == Offload::TcpAndUdp,
        ..Default::default()
    };
    let mut frame = Vec::with_capacity(VNET_HDR_LEN + MAX_PACKET);
    let mut stats = WriteStats::default();

    loop {
        if rx.recv_many(&mut batch, WRITE_BATCH).await == 0 {
            return;
        }
        let Some(tun) = tun.upgrade() else { return };

        if offload == Offload::None {
            coalescer.plan_unmerged(batch.len());
        } else {
            coalescer.plan(&batch);
        }
        stats.packets += batch.len() as u64;
        stats.writes += coalescer.groups.len() as u64;

        for group in &coalescer.groups {
            coalescer.build(group, &batch, &mut frame);
            if let Err(err) = write(&tun, &frame).await {
                if is_fatal(&err) {
                    tracing::error!("Tunnel interface is gone: {err}");
                    return;
                }
                tracing::trace!("Failed to write to the tunnel interface: {err}");
            }
        }
        batch.clear();
    }
}

/// How well merging worked, reported when the writer stops.
#[derive(Default)]
struct WriteStats {
    packets: u64,
    writes: u64,
}

impl Drop for WriteStats {
    fn drop(&mut self) {
        tracing::debug!(
            "Tunnel interface writer: {} packets in {} writes",
            self.packets,
            self.writes
        );
    }
}

fn is_fatal(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EBADF) | Some(libc::EBADFD) | Some(libc::ENODEV)
    )
}

/// The `virtio_net_hdr` of a frame, in host byte order as TUN uses it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct VnetHdr {
    flags: u8,
    gso_type: u8,
    /// Length of the headers in front of the payload to segment.
    hdr_len: u16,
    /// Payload bytes per segment.
    gso_size: u16,
    /// Where the transport header starts.
    csum_start: u16,
    /// Where the checksum sits in the transport header.
    csum_offset: u16,
}

impl VnetHdr {
    /// Splits a frame into its header and the packet behind it.
    fn parse(frame: &[u8]) -> Option<(Self, &[u8])> {
        let (header, packet) = frame.split_at_checked(VNET_HDR_LEN)?;
        let field = |at: usize| u16::from_ne_bytes([header[at], header[at + 1]]);
        Some((
            Self {
                flags: header[0],
                gso_type: header[1],
                hdr_len: field(2),
                gso_size: field(4),
                csum_start: field(6),
                csum_offset: field(8),
            },
            packet,
        ))
    }

    fn write(&self, header: &mut [u8]) {
        header[0] = self.flags;
        header[1] = self.gso_type;
        header[2..4].copy_from_slice(&self.hdr_len.to_ne_bytes());
        header[4..6].copy_from_slice(&self.gso_size.to_ne_bytes());
        header[6..8].copy_from_slice(&self.csum_start.to_ne_bytes());
        header[8..10].copy_from_slice(&self.csum_offset.to_ne_bytes());
    }
}

/// Adds `data` to an Internet checksum in progress. `data` must start at an
/// even offset of what is being summed.
fn sum(data: &[u8], mut acc: u64) -> u64 {
    let (words, rest) = data.as_chunks::<4>();
    for word in words {
        acc += u64::from(u32::from_be_bytes(*word));
    }
    match *rest {
        [a] => acc += u64::from(a) << 8,
        [a, b] => acc += u64::from(u16::from_be_bytes([a, b])),
        [a, b, c] => acc += u64::from(u16::from_be_bytes([a, b])) + (u64::from(c) << 8),
        _ => {}
    }
    acc
}

fn fold(mut acc: u64) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

/// The pseudo header sum for `l4_len` bytes of `protocol` in `packet`.
fn pseudo_sum(packet: &[u8], v6: bool, protocol: u8, l4_len: usize) -> u64 {
    let addresses = if v6 { &packet[8..40] } else { &packet[12..20] };
    sum(addresses, u64::from(protocol) + l4_len as u64)
}

fn tcp_pseudo_sum(packet: &[u8], v6: bool, tcp_len: usize) -> u64 {
    pseudo_sum(packet, v6, IP_PROTOCOL_TCP, tcp_len)
}

fn put_u16(packet: &mut [u8], at: usize, value: u16) {
    packet[at..at + 2].copy_from_slice(&value.to_be_bytes());
}

fn get_u16(packet: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([packet[at], packet[at + 1]])
}

fn get_u32(packet: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([packet[at], packet[at + 1], packet[at + 2], packet[at + 3]])
}

/// Sets the length field of the IP header and, for IPv4, its checksum.
/// `l4` is where the transport header starts.
fn set_ip_length(packet: &mut [u8], v6: bool, l4: usize) {
    let total = packet.len();
    if v6 {
        put_u16(packet, 4, (total - 40) as u16);
    } else {
        put_u16(packet, 2, total as u16);
        put_u16(packet, 10, 0);
        let checksum = !fold(sum(&packet[..l4], 0));
        put_u16(packet, 10, checksum);
    }
}

/// Turns one frame read from the interface into the packets it stands for.
fn segment(
    frame: &[u8],
    pool: &PacketBufPool,
    out: &mut Vec<Packet<Ip>>,
) -> Result<(), &'static str> {
    let (header, packet) = VnetHdr::parse(frame).ok_or("shorter than its header")?;

    match header.gso_type & !VNET_GSO_ECN {
        VNET_GSO_NONE => {
            let mut whole = pool.get();
            let buf = whole.buf_mut();
            buf.clear();
            buf.extend_from_slice(packet);
            if header.flags & VNET_F_NEEDS_CSUM != 0 {
                finish_checksum(buf, &header)?;
            }
            out.push(whole.try_into_ip().map_err(|_| "not an IP packet")?);
            Ok(())
        }
        VNET_GSO_TCPV4 | VNET_GSO_TCPV6 => split_tcp(&header, packet, pool, out),
        VNET_GSO_UDP_L4 => split_udp(&header, packet, pool, out),
        _ => Err("unsupported offload type"),
    }
}

/// Completes a checksum the kernel left at the pseudo header sum.
fn finish_checksum(packet: &mut [u8], header: &VnetHdr) -> Result<(), &'static str> {
    let start = usize::from(header.csum_start);
    let field = start + usize::from(header.csum_offset);
    if field + 2 > packet.len() {
        return Err("checksum outside the packet");
    }
    let checksum = !fold(sum(&packet[start..], 0));
    put_u16(packet, field, checksum);
    Ok(())
}

/// Cuts a large TCP packet into segments of `gso_size` payload bytes, each
/// with complete headers and checksums.
fn split_tcp(
    header: &VnetHdr,
    packet: &[u8],
    pool: &PacketBufPool,
    out: &mut Vec<Packet<Ip>>,
) -> Result<(), &'static str> {
    let v6 = match packet.first().map(|byte| byte >> 4) {
        Some(4) => false,
        Some(6) => true,
        _ => return Err("not an IP packet"),
    };
    let l4 = usize::from(header.csum_start);
    if l4 < if v6 { 40 } else { 20 } || packet.len() < l4 + 20 {
        return Err("TCP header outside the packet");
    }
    let data = l4 + usize::from(packet[l4 + 12] >> 4) * 4;
    if data < l4 + 20 || packet.len() <= data {
        return Err("no TCP payload to segment");
    }
    let size = usize::from(header.gso_size);
    if size == 0 {
        return Err("segment size of zero");
    }

    let (headers, payload) = packet.split_at(data);
    let sequence = get_u32(packet, l4 + 4);
    let identification = get_u16(packet, 4);
    let flags = packet[l4 + 13];
    let count = payload.len().div_ceil(size);

    for (index, chunk) in payload.chunks(size).enumerate() {
        let mut segment = pool.get();
        let buf = segment.buf_mut();
        buf.clear();
        buf.extend_from_slice(headers);
        buf.extend_from_slice(chunk);

        if !v6 {
            put_u16(buf, 4, identification.wrapping_add(index as u16));
        }
        set_ip_length(buf, v6, l4);

        let offset = (index * size) as u32;
        buf[l4 + 4..l4 + 8].copy_from_slice(&sequence.wrapping_add(offset).to_be_bytes());

        // FIN and PSH belong to the end of the data, CWR to its start.
        let mut segment_flags = flags;
        if index + 1 != count {
            segment_flags &= !(TCP_FIN | TCP_PSH);
        }
        if index != 0 {
            segment_flags &= !TCP_CWR;
        }
        buf[l4 + 13] = segment_flags;

        put_u16(buf, l4 + TCP_CHECKSUM, 0);
        let tcp_len = buf.len() - l4;
        let checksum = !fold(sum(&buf[l4..], tcp_pseudo_sum(buf, v6, tcp_len)));
        put_u16(buf, l4 + TCP_CHECKSUM, checksum);

        out.push(segment.try_into_ip().map_err(|_| "not an IP packet")?);
    }

    Ok(())
}

/// Cuts a large UDP packet into datagrams of `gso_size` payload bytes.
fn split_udp(
    header: &VnetHdr,
    packet: &[u8],
    pool: &PacketBufPool,
    out: &mut Vec<Packet<Ip>>,
) -> Result<(), &'static str> {
    let v6 = match packet.first().map(|byte| byte >> 4) {
        Some(4) => false,
        Some(6) => true,
        _ => return Err("not an IP packet"),
    };
    let l4 = usize::from(header.csum_start);
    let data = l4 + UDP_HEADER_LEN;
    if l4 < if v6 { 40 } else { 20 } || packet.len() <= data {
        return Err("no UDP payload to segment");
    }
    let size = usize::from(header.gso_size);
    if size == 0 {
        return Err("segment size of zero");
    }

    let (headers, payload) = packet.split_at(data);
    let identification = get_u16(packet, 4);

    for (index, chunk) in payload.chunks(size).enumerate() {
        let mut datagram = pool.get();
        let buf = datagram.buf_mut();
        buf.clear();
        buf.extend_from_slice(headers);
        buf.extend_from_slice(chunk);

        if !v6 {
            put_u16(buf, 4, identification.wrapping_add(index as u16));
        }
        set_ip_length(buf, v6, l4);

        let udp_len = buf.len() - l4;
        put_u16(buf, l4 + 4, udp_len as u16);
        put_u16(buf, l4 + UDP_CHECKSUM, 0);
        let checksum = !fold(sum(
            &buf[l4..],
            pseudo_sum(buf, v6, IP_PROTOCOL_UDP, udp_len),
        ));
        // Zero means "no checksum" in UDP; the value zero is sent as ones.
        put_u16(
            buf,
            l4 + UDP_CHECKSUM,
            if checksum == 0 { 0xffff } else { checksum },
        );

        out.push(datagram.try_into_ip().map_err(|_| "not an IP packet")?);
    }

    Ok(())
}

/// Addresses, protocol and ports of a flow, one direction.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    addresses: [u8; 32],
    ports: [u8; 4],
    protocol: u8,
    v6: bool,
}

/// What is specific to the transport protocol of a [`Flow`] packet.
#[derive(Clone, Copy)]
enum Transport {
    Tcp { sequence: u32, flags: u8 },
    Udp,
}

/// A TCP or UDP packet without IP options, extension headers or
/// fragmentation.
struct Flow {
    key: FlowKey,
    v6: bool,
    /// Where the transport header starts.
    l4: usize,
    /// Where the payload starts.
    data: usize,
    transport: Transport,
}

impl Flow {
    fn parse(packet: &[u8]) -> Option<Self> {
        let (v6, l4, protocol) = match *packet.first()? {
            0x45 => {
                let fragmented = packet.len() < 28 || get_u16(packet, 6) & 0x3fff != 0;
                if fragmented || usize::from(get_u16(packet, 2)) != packet.len() {
                    return None;
                }
                (false, 20, packet[9])
            }
            byte if byte >> 4 == 6 => {
                if packet.len() < 48 || usize::from(get_u16(packet, 4)) + 40 != packet.len() {
                    return None;
                }
                (true, 40, packet[6])
            }
            _ => return None,
        };

        let (data, transport) = match protocol {
            IP_PROTOCOL_TCP => {
                if packet.len() < l4 + 20 {
                    return None;
                }
                let data = l4 + usize::from(packet[l4 + 12] >> 4) * 4;
                if data < l4 + 20 || data > packet.len() {
                    return None;
                }
                let transport = Transport::Tcp {
                    sequence: get_u32(packet, l4 + 4),
                    flags: packet[l4 + 13],
                };
                (data, transport)
            }
            IP_PROTOCOL_UDP => {
                if usize::from(get_u16(packet, l4 + 4)) != packet.len() - l4 {
                    return None;
                }
                (l4 + UDP_HEADER_LEN, Transport::Udp)
            }
            _ => return None,
        };

        let mut key = FlowKey {
            addresses: [0; 32],
            ports: [0; 4],
            protocol,
            v6,
        };
        let addresses = if v6 { &packet[8..40] } else { &packet[12..20] };
        key.addresses[..addresses.len()].copy_from_slice(addresses);
        key.ports.copy_from_slice(&packet[l4..l4 + 4]);

        Some(Self {
            key,
            v6,
            l4,
            data,
            transport,
        })
    }

    /// Whether the packet may share a frame with others of its flow.
    ///
    /// Of TCP only plain data segments: ACK, with or without PSH. Of UDP
    /// only datagrams with a checksum, since one without cannot be told
    /// from a corrupted one, and only where the kernel segments UDP.
    fn mergeable(&self, packet: &[u8], udp: bool) -> bool {
        if self.data >= packet.len() {
            return false;
        }
        match self.transport {
            Transport::Tcp { flags, .. } => flags & !TCP_PSH == TCP_ACK,
            Transport::Udp => udp && get_u16(packet, self.l4 + UDP_CHECKSUM) != 0,
        }
    }

    fn checksum_ok(&self, packet: &[u8]) -> bool {
        let l4_len = packet.len() - self.l4;
        fold(sum(
            &packet[self.l4..],
            pseudo_sum(packet, self.v6, self.key.protocol, l4_len),
        )) == 0xffff
    }

    /// Whether `packet` continues the flow of `head` with nothing changed
    /// that the kernel takes from the first packet when it rebuilds the
    /// others.
    fn same_headers(&self, head: &[u8], packet: &[u8]) -> bool {
        let l4 = self.l4;
        let ip = if self.v6 {
            // Traffic class, flow label, hop limit.
            head[..4] == packet[..4] && head[7] == packet[7]
        } else {
            // Type of service, don't-fragment, time to live.
            head[1] == packet[1] && head[6] == packet[6] && head[8] == packet[8]
        };
        ip && match self.transport {
            // Acknowledgement number, window, options.
            Transport::Tcp { .. } => {
                head[l4 + 8..l4 + 12] == packet[l4 + 8..l4 + 12]
                    && head[l4 + 14..l4 + 16] == packet[l4 + 14..l4 + 16]
                    && head[l4 + 20..self.data] == packet[l4 + 20..self.data]
            }
            Transport::Udp => true,
        }
    }
}

/// Packets of a batch that leave in one frame.
struct Group {
    /// First and last packet, as indexes into the batch.
    head: usize,
    tail: usize,
    count: usize,
    /// Length of the merged packet.
    len: usize,
    v6: bool,
    l4: usize,
    data: usize,
    /// Payload bytes per segment: the payload of the first packet.
    segment_size: usize,
    udp: bool,
    /// TCP: sequence number the next segment must carry.
    next_sequence: u32,
    /// TCP: the last segment carried PSH.
    push: bool,
    /// More segments may follow.
    open: bool,
    /// The first packet's checksum was found good.
    head_verified: bool,
}

/// Merges consecutive packets of a flow in a batch.
///
/// Packets leave in the order they came: a packet that cannot extend its
/// flow's group ends that group, so nothing of a flow overtakes it.
#[derive(Default)]
struct Coalescer {
    /// Merge UDP datagrams too.
    udp: bool,
    groups: Vec<Group>,
    /// For each packet, the next packet of its group.
    next: Vec<usize>,
    /// The group each flow may still extend.
    flows: HashMap<FlowKey, usize>,
}

/// End of a group's chain in [`Coalescer::next`].
const END: usize = usize::MAX;

impl Coalescer {
    fn reset(&mut self, packets: usize) {
        self.groups.clear();
        self.flows.clear();
        self.next.clear();
        self.next.resize(packets, END);
    }

    /// One group per packet.
    fn plan_unmerged(&mut self, packets: usize) {
        self.reset(packets);
        for index in 0..packets {
            self.alone(index);
        }
    }

    fn plan<P: AsRef<[u8]>>(&mut self, batch: &[P]) {
        self.reset(batch.len());

        for (index, packet) in batch.iter().enumerate() {
            let packet = packet.as_ref();
            let Some(flow) = Flow::parse(packet) else {
                self.alone(index);
                continue;
            };
            if !flow.mergeable(packet, self.udp) {
                self.flows.remove(&flow.key);
                self.alone(index);
                continue;
            }
            if let Some(&group) = self.flows.get(&flow.key)
                && self.append(group, batch, index, &flow)
            {
                continue;
            }

            let payload = packet.len() - flow.data;
            let (udp, next_sequence, push) = match flow.transport {
                Transport::Tcp { sequence, flags } => (
                    false,
                    sequence.wrapping_add(payload as u32),
                    flags & TCP_PSH != 0,
                ),
                Transport::Udp => (true, 0, false),
            };
            self.flows.insert(flow.key, self.groups.len());
            self.groups.push(Group {
                head: index,
                tail: index,
                count: 1,
                len: packet.len(),
                v6: flow.v6,
                l4: flow.l4,
                data: flow.data,
                segment_size: payload,
                udp,
                next_sequence,
                push,
                open: !push,
                head_verified: false,
            });
        }
    }

    fn alone(&mut self, index: usize) {
        self.groups.push(Group {
            head: index,
            tail: index,
            count: 1,
            len: 0,
            v6: false,
            l4: 0,
            data: 0,
            segment_size: 0,
            udp: false,
            next_sequence: 0,
            push: false,
            open: false,
            head_verified: false,
        });
    }

    /// Adds packet `index` to `group` if it is the next segment of it.
    fn append<P: AsRef<[u8]>>(
        &mut self,
        group: usize,
        batch: &[P],
        index: usize,
        flow: &Flow,
    ) -> bool {
        let group = &mut self.groups[group];
        let head = batch[group.head].as_ref();
        let packet = batch[index].as_ref();
        let payload = packet.len() - flow.data;

        let next_in_line = match flow.transport {
            Transport::Tcp { sequence, .. } => sequence == group.next_sequence,
            Transport::Udp => group.count < UDP_MAX_SEGMENTS,
        };
        if !group.open
            || !next_in_line
            || flow.data != group.data
            || payload > group.segment_size
            || group.len + payload > MAX_PACKET
            || !flow.same_headers(head, packet)
        {
            return false;
        }

        // The kernel computes the checksums of what it cuts the merged
        // packet into, which would make a corrupted segment look sound.
        // So only segments that arrived sound are merged.
        if !group.head_verified {
            if !flow.checksum_ok(head) {
                group.open = false;
                return false;
            }
            group.head_verified = true;
        }
        if !flow.checksum_ok(packet) {
            return false;
        }

        self.next[group.tail] = index;
        group.tail = index;
        group.count += 1;
        group.len += payload;
        group.next_sequence = group.next_sequence.wrapping_add(payload as u32);
        if let Transport::Tcp { flags, .. } = flow.transport
            && flags & TCP_PSH != 0
        {
            group.push = true;
            group.open = false;
        }
        // Only the last segment may be shorter than the rest.
        if payload < group.segment_size {
            group.open = false;
        }
        true
    }

    /// Writes the frame of `group` into `frame`.
    fn build<P: AsRef<[u8]>>(&self, group: &Group, batch: &[P], frame: &mut Vec<u8>) {
        let head = batch[group.head].as_ref();

        frame.clear();
        frame.resize(VNET_HDR_LEN, 0);
        frame.extend_from_slice(head);
        if group.count == 1 {
            return;
        }

        let mut index = self.next[group.head];
        while index != END {
            frame.extend_from_slice(&batch[index].as_ref()[group.data..]);
            index = self.next[index];
        }

        let (header, packet) = frame.split_at_mut(VNET_HDR_LEN);
        let (gso_type, protocol, checksum) = match (group.udp, group.v6) {
            (true, _) => (VNET_GSO_UDP_L4, IP_PROTOCOL_UDP, UDP_CHECKSUM),
            (false, false) => (VNET_GSO_TCPV4, IP_PROTOCOL_TCP, TCP_CHECKSUM),
            (false, true) => (VNET_GSO_TCPV6, IP_PROTOCOL_TCP, TCP_CHECKSUM),
        };
        VnetHdr {
            flags: VNET_F_NEEDS_CSUM,
            gso_type,
            hdr_len: group.data as u16,
            gso_size: group.segment_size as u16,
            csum_start: group.l4 as u16,
            csum_offset: checksum as u16,
        }
        .write(header);

        set_ip_length(packet, group.v6, group.l4);
        let l4_len = packet.len() - group.l4;
        if group.udp {
            put_u16(packet, group.l4 + 4, l4_len as u16);
        } else if group.push {
            packet[group.l4 + 13] |= TCP_PSH;
        }
        // The kernel finishes the checksum of each segment from the pseudo
        // header sum of the whole.
        let pseudo = fold(pseudo_sum(packet, group.v6, protocol, l4_len));
        put_u16(packet, group.l4 + checksum, pseudo);
    }
}

#[cfg(test)]
mod tests {
    use gotatun::packet::PacketBufPool;

    use super::*;

    const MSS: usize = 1200;

    struct Segment {
        v6: bool,
        source_port: u16,
        sequence: u32,
        acknowledgement: u32,
        flags: u8,
        identification: u16,
        payload: Vec<u8>,
    }

    impl Segment {
        fn new(sequence: u32, payload_len: usize) -> Self {
            Self {
                v6: false,
                source_port: 443,
                sequence,
                acknowledgement: 7000,
                flags: TCP_ACK,
                identification: 0,
                payload: (0..payload_len)
                    .map(|i| (i as u32).wrapping_add(sequence) as u8)
                    .collect(),
            }
        }

        fn v6(mut self) -> Self {
            self.v6 = true;
            self
        }

        fn flags(mut self, flags: u8) -> Self {
            self.flags = flags;
            self
        }

        fn port(mut self, port: u16) -> Self {
            self.source_port = port;
            self
        }

        fn id(mut self, identification: u16) -> Self {
            self.identification = identification;
            self
        }

        /// The packet with a timestamp option and complete checksums.
        fn build(&self) -> Vec<u8> {
            let l4 = if self.v6 { 40 } else { 20 };
            let mut packet = vec![0u8; l4 + 32];
            if self.v6 {
                packet[0] = 0x60;
                packet[6] = IP_PROTOCOL_TCP;
                packet[7] = 61;
                packet[8..24].copy_from_slice(&[0x20; 16]);
                packet[24..40].copy_from_slice(&[0xfd; 16]);
            } else {
                packet[0] = 0x45;
                put_u16(&mut packet, 4, self.identification);
                packet[6] = 0x40;
                packet[8] = 61;
                packet[9] = IP_PROTOCOL_TCP;
                packet[12..16].copy_from_slice(&[203, 0, 113, 9]);
                packet[16..20].copy_from_slice(&[10, 2, 0, 5]);
            }
            put_u16(&mut packet, l4, self.source_port);
            put_u16(&mut packet, l4 + 2, 51000);
            packet[l4 + 4..l4 + 8].copy_from_slice(&self.sequence.to_be_bytes());
            packet[l4 + 8..l4 + 12].copy_from_slice(&self.acknowledgement.to_be_bytes());
            packet[l4 + 12] = 8 << 4;
            packet[l4 + 13] = self.flags;
            put_u16(&mut packet, l4 + 14, 501);
            packet[l4 + 20..l4 + 32]
                .copy_from_slice(&[1, 1, 8, 10, 0, 0, 0x30, 0x39, 0, 0, 0x01, 0x02]);
            packet.extend_from_slice(&self.payload);

            set_ip_length(&mut packet, self.v6, l4);
            let tcp_len = packet.len() - l4;
            let checksum = !fold(sum(
                &packet[l4..],
                tcp_pseudo_sum(&packet, self.v6, tcp_len),
            ));
            put_u16(&mut packet, l4 + TCP_CHECKSUM, checksum);
            packet
        }
    }

    /// `count` full segments of one flow, in order.
    fn burst(count: usize, v6: bool) -> Vec<Vec<u8>> {
        (0..count)
            .map(|i| {
                let segment = Segment::new(1000 + (i * MSS) as u32, MSS).id(40 + i as u16);
                if v6 { segment.v6() } else { segment }.build()
            })
            .collect()
    }

    fn frames(batch: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut coalescer = Coalescer {
            udp: true,
            ..Default::default()
        };
        coalescer.plan(batch);
        coalescer
            .groups
            .iter()
            .map(|group| {
                let mut frame = Vec::new();
                coalescer.build(group, batch, &mut frame);
                frame
            })
            .collect()
    }

    fn segments(frame: &[u8]) -> Vec<Vec<u8>> {
        let pool = PacketBufPool::new(4);
        let mut out = Vec::new();
        segment(frame, &pool, &mut out).unwrap();
        out.into_iter()
            .map(|packet| packet.into_bytes().to_vec())
            .collect()
    }

    fn gso_type(frame: &[u8]) -> u8 {
        VnetHdr::parse(frame).unwrap().0.gso_type
    }

    #[test]
    fn checksum_of_a_known_header() {
        // The IPv4 header example from RFC 1071 discussions: checksum b861.
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(!fold(sum(&header, 0)), 0xb861);
    }

    #[test]
    fn checksum_of_an_odd_length() {
        assert_eq!(fold(sum(&[0x01, 0x02, 0x03], 0)), 0x0402);
        assert_eq!(fold(sum(&[0xff, 0xff, 0xff, 0xff, 0x01], 0)), 0x0100);
    }

    #[test]
    fn a_burst_becomes_one_frame_and_splits_back() {
        for v6 in [false, true] {
            let batch = burst(40, v6);
            let frames = frames(&batch);

            assert_eq!(frames.len(), 1);
            let (header, packet) = VnetHdr::parse(&frames[0]).unwrap();
            let l4 = if v6 { 40 } else { 20 };
            assert_eq!(
                header,
                VnetHdr {
                    flags: VNET_F_NEEDS_CSUM,
                    gso_type: if v6 { VNET_GSO_TCPV6 } else { VNET_GSO_TCPV4 },
                    hdr_len: l4 + 32,
                    gso_size: MSS as u16,
                    csum_start: l4,
                    csum_offset: 16,
                }
            );
            assert_eq!(packet.len(), usize::from(l4) + 32 + 40 * MSS);

            assert_eq!(segments(&frames[0]), batch);
        }
    }

    #[test]
    fn a_short_last_segment_with_push_ends_the_group() {
        let batch = vec![
            Segment::new(1000, MSS).id(1).build(),
            Segment::new(1000 + MSS as u32, 300)
                .id(2)
                .flags(TCP_ACK | TCP_PSH)
                .build(),
            Segment::new(1300 + MSS as u32, MSS).id(3).build(),
        ];
        let frames = frames(&batch);

        assert_eq!(frames.len(), 2);
        assert_eq!(segments(&frames[0]), batch[..2]);
        assert_eq!(gso_type(&frames[1]), VNET_GSO_NONE);
        assert_eq!(frames[1][VNET_HDR_LEN..], batch[2]);
    }

    #[test]
    fn a_gap_in_the_sequence_is_not_merged() {
        let batch = vec![
            Segment::new(1000, MSS).build(),
            Segment::new(1000 + 2 * MSS as u32, MSS).build(),
        ];
        let frames = frames(&batch);

        assert_eq!(frames.len(), 2);
        assert!(frames.iter().all(|frame| gso_type(frame) == VNET_GSO_NONE));
    }

    #[test]
    fn a_changed_acknowledgement_is_not_merged() {
        let mut second = Segment::new(1000 + MSS as u32, MSS);
        second.acknowledgement += 1;
        let batch = vec![Segment::new(1000, MSS).build(), second.build()];

        assert_eq!(frames(&batch).len(), 2);
    }

    #[test]
    fn a_corrupted_segment_is_not_merged() {
        let mut batch = burst(3, false);
        let last = batch[1].len() - 1;
        batch[1][last] ^= 0x01;
        let frames = frames(&batch);

        // The sound first packet, then the corrupted one, then the third:
        // it cannot join a group whose first packet is unsound.
        assert_eq!(frames.len(), 3);
        for (frame, packet) in frames.iter().zip(&batch) {
            assert_eq!(gso_type(frame), VNET_GSO_NONE);
            assert_eq!(&frame[VNET_HDR_LEN..], packet);
        }
    }

    #[test]
    fn a_corrupted_first_segment_is_not_merged() {
        let mut batch = burst(2, false);
        let last = batch[0].len() - 1;
        batch[0][last] ^= 0x01;

        assert_eq!(frames(&batch).len(), 2);
    }

    #[test]
    fn interleaved_flows_are_merged_separately() {
        let mut batch = Vec::new();
        for i in 0..6u32 {
            for port in [443, 8443] {
                batch.push(
                    Segment::new(1000 + i * MSS as u32, MSS)
                        .port(port)
                        .id(i as u16)
                        .build(),
                );
            }
        }
        let frames = frames(&batch);

        assert_eq!(frames.len(), 2);
        let first: Vec<_> = batch.iter().step_by(2).cloned().collect();
        let second: Vec<_> = batch.iter().skip(1).step_by(2).cloned().collect();
        assert_eq!(segments(&frames[0]), first);
        assert_eq!(segments(&frames[1]), second);
    }

    #[test]
    fn nothing_overtakes_a_packet_that_cannot_be_merged() {
        let batch = vec![
            Segment::new(1000, MSS).id(1).build(),
            // A FIN in the middle: goes alone and ends the group before it.
            Segment::new(5000, MSS).flags(TCP_ACK | TCP_FIN).build(),
            Segment::new(1000 + MSS as u32, MSS).id(2).build(),
        ];
        let frames = frames(&batch);

        assert_eq!(frames.len(), 3);
        for (frame, packet) in frames.iter().zip(&batch) {
            assert_eq!(&frame[VNET_HDR_LEN..], packet);
        }
    }

    #[test]
    fn other_packets_pass_unchanged() {
        let mut udp = vec![0u8; 60];
        udp[0] = 0x45;
        udp[3] = 60;
        udp[9] = 17;
        let ack = Segment::new(1000, 0).build();
        let batch = vec![udp, ack];
        let frames = frames(&batch);

        assert_eq!(frames.len(), 2);
        for (frame, packet) in frames.iter().zip(&batch) {
            assert_eq!(frame[..VNET_HDR_LEN], [0; VNET_HDR_LEN]);
            assert_eq!(&frame[VNET_HDR_LEN..], packet);
        }
    }

    #[test]
    fn a_merged_packet_stays_within_the_largest_ip_packet() {
        let batch = burst(60, false);
        let frames = frames(&batch);

        assert_eq!(frames.len(), 2);
        assert!(
            frames
                .iter()
                .all(|frame| frame.len() - VNET_HDR_LEN <= MAX_PACKET)
        );
        let split: Vec<_> = frames.iter().flat_map(|frame| segments(frame)).collect();
        assert_eq!(split, batch);
    }

    #[test]
    fn splitting_moves_the_flags_to_the_right_segments() {
        let l4 = 20;
        let mut large = Segment::new(1000, 2 * MSS + 100)
            .flags(TCP_ACK | TCP_PSH | TCP_FIN | TCP_CWR)
            .id(9)
            .build();
        // As the kernel hands it over: pseudo header sum in the checksum.
        let tcp_len = large.len() - l4;
        let pseudo = fold(tcp_pseudo_sum(&large, false, tcp_len));
        put_u16(&mut large, l4 + TCP_CHECKSUM, pseudo);

        let mut frame = vec![0u8; VNET_HDR_LEN];
        VnetHdr {
            flags: VNET_F_NEEDS_CSUM,
            gso_type: VNET_GSO_TCPV4 | VNET_GSO_ECN,
            hdr_len: 52,
            gso_size: MSS as u16,
            csum_start: l4 as u16,
            csum_offset: 16,
        }
        .write(&mut frame);
        frame.extend_from_slice(&large);

        let split = segments(&frame);
        assert_eq!(split.len(), 3);
        let flags: Vec<u8> = split.iter().map(|packet| packet[l4 + 13]).collect();
        assert_eq!(
            flags,
            [TCP_ACK | TCP_CWR, TCP_ACK, TCP_ACK | TCP_PSH | TCP_FIN]
        );
        let lengths: Vec<usize> = split.iter().map(|packet| packet.len() - 52).collect();
        assert_eq!(lengths, [MSS, MSS, 100]);
        for (index, packet) in split.iter().enumerate() {
            let flow = Flow::parse(packet).unwrap();
            assert!(flow.checksum_ok(packet));
            assert_eq!(get_u32(packet, l4 + 4), 1000 + (index * MSS) as u32);
            assert_eq!(get_u16(packet, 4), 9 + index as u16);
            assert_eq!(fold(sum(&packet[..20], 0)), 0xffff);
        }
    }

    /// A UDP datagram with a complete checksum.
    fn datagram(v6: bool, identification: u16, payload_len: usize, fill: u8) -> Vec<u8> {
        let l4 = if v6 { 40 } else { 20 };
        let mut packet = vec![0u8; l4 + UDP_HEADER_LEN];
        if v6 {
            packet[0] = 0x60;
            packet[6] = IP_PROTOCOL_UDP;
            packet[7] = 58;
            packet[8..24].copy_from_slice(&[0x20; 16]);
            packet[24..40].copy_from_slice(&[0xfd; 16]);
        } else {
            packet[0] = 0x45;
            put_u16(&mut packet, 4, identification);
            packet[6] = 0x40;
            packet[8] = 58;
            packet[9] = IP_PROTOCOL_UDP;
            packet[12..16].copy_from_slice(&[203, 0, 113, 9]);
            packet[16..20].copy_from_slice(&[10, 2, 0, 5]);
        }
        put_u16(&mut packet, l4, 443);
        put_u16(&mut packet, l4 + 2, 51000);
        packet.extend((0..payload_len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(fill)));

        set_ip_length(&mut packet, v6, l4);
        let udp_len = packet.len() - l4;
        put_u16(&mut packet, l4 + 4, udp_len as u16);
        let checksum = !fold(sum(
            &packet[l4..],
            pseudo_sum(&packet, v6, IP_PROTOCOL_UDP, udp_len),
        ));
        put_u16(&mut packet, l4 + UDP_CHECKSUM, checksum);
        packet
    }

    #[test]
    fn datagrams_of_a_flow_become_one_frame_and_split_back() {
        for v6 in [false, true] {
            let mut batch: Vec<_> = (0..20)
                .map(|i| datagram(v6, 300 + i, 1250, i as u8))
                .collect();
            // A shorter one ends the run; the next starts another.
            batch.push(datagram(v6, 320, 700, 20));
            batch.push(datagram(v6, 321, 1250, 21));
            let frames = frames(&batch);

            assert_eq!(frames.len(), 2);
            let (header, packet) = VnetHdr::parse(&frames[0]).unwrap();
            let l4 = if v6 { 40 } else { 20 };
            assert_eq!(
                header,
                VnetHdr {
                    flags: VNET_F_NEEDS_CSUM,
                    gso_type: VNET_GSO_UDP_L4,
                    hdr_len: l4 + 8,
                    gso_size: 1250,
                    csum_start: l4,
                    csum_offset: 6,
                }
            );
            assert_eq!(
                usize::from(get_u16(packet, usize::from(l4) + 4)),
                packet.len() - usize::from(l4)
            );
            assert_eq!(segments(&frames[0]), batch[..21]);
            assert_eq!(gso_type(&frames[1]), VNET_GSO_NONE);
        }
    }

    #[test]
    fn datagrams_are_merged_only_where_the_kernel_segments_them() {
        let batch: Vec<_> = (0..4).map(|i| datagram(false, i, 1250, 0)).collect();
        let mut coalescer = Coalescer::default();
        coalescer.plan(&batch);

        assert_eq!(coalescer.groups.len(), 4);
    }

    #[test]
    fn a_frame_holds_no_more_datagrams_than_the_kernel_takes() {
        let batch: Vec<_> = (0..100).map(|i| datagram(false, i, 500, i as u8)).collect();
        let frames = frames(&batch);

        assert_eq!(frames.len(), 2);
        assert_eq!(segments(&frames[0]).len(), UDP_MAX_SEGMENTS);
        let split: Vec<_> = frames.iter().flat_map(|frame| segments(frame)).collect();
        assert_eq!(split, batch);
    }

    #[test]
    fn datagrams_without_a_checksum_or_with_a_wrong_one_are_not_merged() {
        let mut batch: Vec<_> = (0..4).map(|i| datagram(false, i, 1250, 0)).collect();
        put_u16(&mut batch[1], 20 + UDP_CHECKSUM, 0);
        batch[3][40] ^= 0x10;
        let frames = frames(&batch);

        assert_eq!(frames.len(), 4);
        for (frame, packet) in frames.iter().zip(&batch) {
            assert_eq!(gso_type(frame), VNET_GSO_NONE);
            assert_eq!(&frame[VNET_HDR_LEN..], packet);
        }
    }

    #[test]
    fn a_partial_checksum_is_finished() {
        // UDP datagram with the pseudo header sum where the checksum goes.
        let mut packet = vec![0u8; 20 + 8 + 5];
        packet[0] = 0x45;
        packet[3] = 33;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 2, 0, 5]);
        packet[16..20].copy_from_slice(&[9, 9, 9, 9]);
        put_u16(&mut packet, 20, 40000);
        put_u16(&mut packet, 22, 53);
        put_u16(&mut packet, 24, 13);
        packet[28..].copy_from_slice(b"hello");
        let pseudo = fold(sum(&packet[12..20], 17 + 13));
        put_u16(&mut packet, 26, pseudo);

        let mut frame = vec![0u8; VNET_HDR_LEN];
        VnetHdr {
            flags: VNET_F_NEEDS_CSUM,
            csum_start: 20,
            csum_offset: 6,
            ..Default::default()
        }
        .write(&mut frame);
        frame.extend_from_slice(&packet);

        let out = segments(&frame);
        assert_eq!(out.len(), 1);
        assert_eq!(
            fold(sum(&out[0][20..], sum(&out[0][12..20], 17 + 13))),
            0xffff
        );
    }

    /// Sets the addresses and ports of a [`datagram`] and redoes its checksum.
    fn readdress(packet: &mut [u8], source: [u8; 4], destination: [u8; 4], ports: (u16, u16)) {
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        put_u16(packet, 20, ports.0);
        put_u16(packet, 22, ports.1);
        set_ip_length(packet, false, 20);
        put_u16(packet, 20 + UDP_CHECKSUM, 0);
        let udp_len = packet.len() - 20;
        let checksum = !fold(sum(
            &packet[20..],
            pseudo_sum(packet, false, IP_PROTOCOL_UDP, udp_len),
        ));
        put_u16(packet, 20 + UDP_CHECKSUM, checksum);
    }

    /// The frame formats against a real interface, UDP both ways: the
    /// kernel must deliver every datagram of a merged frame, and what it
    /// hands over as one large packet must split into sound datagrams.
    ///
    /// Run as root in a network namespace of its own:
    /// `unshare -n <test binary> --ignored kernel`.
    #[tokio::test]
    #[ignore = "creates a TUN device; needs root and Linux 6.2"]
    async fn the_kernel_agrees_on_the_frame_format() {
        use std::{os::fd::AsRawFd, time::Duration};
        use tokio::time::timeout;

        const LOCAL: [u8; 4] = [10, 9, 0, 1];
        const PEER: [u8; 4] = [10, 9, 0, 2];

        let mut config = tun::Configuration::default();
        config
            .tun_name("nymtest0")
            .address(std::net::Ipv4Addr::from(LOCAL))
            .netmask((255, 255, 255, 0))
            .mtu(1400)
            .up();
        enable_offload(&mut config);
        let tun = adopt(tun::create_as_async(&config).unwrap()).unwrap();
        assert!(has_vnet_hdr(tun.as_raw_fd()).unwrap());
        assert_eq!(set_offload(tun.as_raw_fd()), Offload::TcpAndUdp);

        let socket = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::from(LOCAL), 5000))
            .await
            .unwrap();

        // In: twenty datagrams in one frame.
        let batch: Vec<_> = (0..20)
            .map(|i| {
                let mut packet = datagram(false, i, 1200, i as u8);
                readdress(&mut packet, PEER, LOCAL, (4000, 5000));
                packet
            })
            .collect();
        let frames = frames(&batch);
        assert_eq!(frames.len(), 1);
        write(&tun, &frames[0]).await.unwrap();

        let mut buf = [0u8; 2000];
        for packet in &batch {
            let (len, from) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
                .await
                .expect("the kernel dropped a merged datagram")
                .unwrap();
            assert_eq!(from, "10.9.0.2:4000".parse().unwrap());
            assert_eq!(buf[..len], packet[28..]);
        }

        // Out: one send of five datagrams' worth, segmented by the kernel.
        let size: libc::c_int = 1000;
        // SAFETY: the option takes an int, passed with its size.
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_UDP,
                libc::UDP_SEGMENT,
                (&raw const size).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(result, 0);
        let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        socket.send_to(&payload, "10.9.0.2:4000").await.unwrap();

        let mut frame = vec![0u8; VNET_HDR_LEN + MAX_PACKET];
        let mut received = Vec::new();
        while received.len() < payload.len() {
            let len = timeout(Duration::from_secs(2), read(&tun, &mut frame))
                .await
                .expect("nothing to read from the interface")
                .unwrap();
            for packet in segments(&frame[..len]) {
                let Some(flow) = Flow::parse(&packet) else {
                    continue;
                };
                if flow.key.protocol != IP_PROTOCOL_UDP || packet[16..20] != PEER {
                    continue;
                }
                assert!(flow.checksum_ok(&packet));
                assert_eq!(packet.len(), 28 + 1000);
                received.extend_from_slice(&packet[28..]);
            }
        }
        assert_eq!(received, payload);
    }

    #[test]
    fn malformed_frames_are_refused() {
        let pool = PacketBufPool::new(1);
        let mut out = Vec::new();

        assert!(segment(&[0; 4], &pool, &mut out).is_err());

        let mut frame = vec![0u8; VNET_HDR_LEN];
        VnetHdr {
            gso_type: VNET_GSO_TCPV4,
            gso_size: 0,
            csum_start: 20,
            ..Default::default()
        }
        .write(&mut frame);
        frame.extend_from_slice(&Segment::new(1, 100).build());
        assert!(segment(&frame, &pool, &mut out).is_err());

        frame.truncate(VNET_HDR_LEN + 30);
        assert!(segment(&frame, &pool, &mut out).is_err());
        assert!(out.is_empty());
    }
}
