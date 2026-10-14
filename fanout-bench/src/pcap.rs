//! Minimal streaming reader for classic pcap files (as written by `tcpdump -w`)
//! that decodes IPv4/UDP packets. pcapng is not supported.

use std::{
    fs::File,
    io::{self, BufReader, ErrorKind, Read},
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
};

const LINKTYPE_ETHERNET: u32 = 1;
const LINKTYPE_RAW: u32 = 101;
const LINKTYPE_LINUX_SLL: u32 = 113;
const LINKTYPE_IPV4: u32 = 228;
const LINKTYPE_LINUX_SLL2: u32 = 276;

/// Largest record we accept; anything bigger means a corrupt file.
const MAX_RECORD_LEN: usize = 256 * 1024;

/// One decoded UDP datagram from a capture.
pub struct UdpPacket<'a> {
    /// Capture timestamp in nanoseconds since the epoch.
    pub ts_ns: u64,
    /// Interface index (Linux "any" captures only; 0 otherwise).
    pub ifindex: u32,
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    /// UDP payload length on the wire, from the UDP header.
    pub payload_len: usize,
    /// The captured part of the payload; shorter than `payload_len` when the
    /// capture snap length cut it off.
    pub payload: &'a [u8],
}

pub struct PcapReader {
    reader: BufReader<File>,
    swapped: bool,
    nanos: bool,
    linktype: u32,
    buf: Vec<u8>,
    ts_ns: u64,
}

impl PcapReader {
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut reader = BufReader::with_capacity(1 << 20, File::open(path)?);
        let mut hdr = [0u8; 24];
        reader.read_exact(&mut hdr)?;
        let (swapped, nanos) = match u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) {
            0xa1b2_c3d4 => (false, false),
            0xa1b2_3c4d => (false, true),
            0xd4c3_b2a1 => (true, false),
            0x4d3c_b2a1 => (true, true),
            _ => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "{}: not a classic pcap file (capture with `tcpdump -w`, not pcapng)",
                        path.display()
                    ),
                ))
            }
        };
        let mut r = Self {
            reader,
            swapped,
            nanos,
            linktype: 0,
            buf: Vec::with_capacity(2048),
            ts_ns: 0,
        };
        r.linktype = r.u32_at(&hdr, 20) & 0x0fff_ffff;
        Ok(r)
    }

    /// Whether timestamps in this file have nanosecond resolution.
    pub fn has_nanos(&self) -> bool {
        self.nanos
    }

    /// Returns the next IPv4/UDP packet, skipping everything else.
    /// A truncated final record (e.g. tcpdump was killed) is treated as EOF.
    pub fn next_udp(&mut self) -> io::Result<Option<UdpPacket<'_>>> {
        loop {
            if !self.read_record()? {
                return Ok(None);
            }
            if decode(self.linktype, &self.buf, self.ts_ns).is_some() {
                break;
            }
        }
        Ok(decode(self.linktype, &self.buf, self.ts_ns))
    }

    fn read_record(&mut self) -> io::Result<bool> {
        let mut hdr = [0u8; 16];
        match self.reader.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(false),
            Err(e) => return Err(e),
        }
        let secs = self.u32_at(&hdr, 0) as u64;
        let frac = self.u32_at(&hdr, 4) as u64;
        let incl_len = self.u32_at(&hdr, 8) as usize;
        if incl_len > MAX_RECORD_LEN {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("record length {incl_len} is implausible; file is corrupt"),
            ));
        }
        self.ts_ns = secs * 1_000_000_000 + if self.nanos { frac } else { frac * 1_000 };
        self.buf.resize(incl_len, 0);
        match self.reader.read_exact(&mut self.buf) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn u32_at(&self, b: &[u8], off: usize) -> u32 {
        let v = [b[off], b[off + 1], b[off + 2], b[off + 3]];
        if self.swapped {
            u32::from_be_bytes(v)
        } else {
            u32::from_le_bytes(v)
        }
    }
}

fn be16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(off)?, *b.get(off + 1)?]))
}

fn be32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn decode(linktype: u32, data: &[u8], ts_ns: u64) -> Option<UdpPacket<'_>> {
    let (mut proto, mut off, ifindex) = match linktype {
        LINKTYPE_ETHERNET => (be16(data, 12)?, 14, 0),
        LINKTYPE_LINUX_SLL => (be16(data, 14)?, 16, 0),
        LINKTYPE_LINUX_SLL2 => (be16(data, 0)?, 20, be32(data, 4)?),
        LINKTYPE_RAW | LINKTYPE_IPV4 => (0x0800, 0, 0),
        _ => return None,
    };
    // Skip 802.1Q / 802.1ad tags (private traffic here rides a VLAN).
    while proto == 0x8100 || proto == 0x88a8 {
        proto = be16(data, off + 2)?;
        off += 4;
    }
    if proto != 0x0800 {
        return None;
    }

    let ip = data.get(off..)?;
    if ip.len() < 20 || ip[0] >> 4 != 4 || ip[9] != 17 {
        return None;
    }
    // Only the first fragment carries the UDP header.
    if u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff != 0 {
        return None;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    let udp = ip.get(ihl..)?;
    if udp.len() < 8 {
        return None;
    }

    let src = SocketAddrV4::new(
        Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
        u16::from_be_bytes([udp[0], udp[1]]),
    );
    let dst = SocketAddrV4::new(
        Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
        u16::from_be_bytes([udp[2], udp[3]]),
    );
    let payload_len = (u16::from_be_bytes([udp[4], udp[5]]) as usize).saturating_sub(8);
    let captured = &udp[8..];
    let payload = &captured[..captured.len().min(payload_len)];

    Some(UdpPacket {
        ts_ns,
        ifindex,
        src,
        dst,
        payload_len,
        payload,
    })
}
