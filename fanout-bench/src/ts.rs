//! Clocks and kernel receive timestamps, for one-way latency measurement
//! between two hosts (`clock-echo` on the forwarder, `stamp-recv` on a
//! receiver).

use std::{
    io, mem,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    os::fd::AsRawFd,
};

pub fn clock_ns(clock: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid pointer to a timespec; the clocks used here always exist.
    unsafe { libc::clock_gettime(clock, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

pub fn realtime_ns() -> u64 {
    clock_ns(libc::CLOCK_REALTIME)
}

pub fn monotonic_ns() -> u64 {
    clock_ns(libc::CLOCK_MONOTONIC)
}

/// CLOCK_REALTIME minus CLOCK_MONOTONIC on this host, from the tightest of a
/// few back-to-back reads (to convert kernel receive timestamps, which are
/// CLOCK_REALTIME, to the monotonic clock the forwarders stamp with).
pub fn realtime_minus_monotonic() -> i64 {
    let mut best = (u64::MAX, 0i64);
    for _ in 0..5 {
        let a = monotonic_ns();
        let r = realtime_ns();
        let b = monotonic_ns();
        if b - a < best.0 {
            best = (b - a, r as i64 - (a + (b - a) / 2) as i64);
        }
    }
    best.1
}

/// Asks the kernel to timestamp every datagram this socket receives.
pub fn enable_rx_timestamps(sock: &UdpSocket) -> io::Result<()> {
    let on: libc::c_int = 1;
    // SAFETY: valid fd and option value.
    let r = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPNS,
            &on as *const _ as *const libc::c_void,
            mem::size_of_val(&on) as libc::socklen_t,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn set_recv_buffer(sock: &UdpSocket, bytes: libc::c_int) {
    // SAFETY: valid fd and option value. Best effort: the default is fine too.
    unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &bytes as *const _ as *const libc::c_void,
            mem::size_of_val(&bytes) as libc::socklen_t,
        );
    }
}

/// Receives one datagram: (length, source, kernel receive time in
/// CLOCK_REALTIME ns; the current time if the kernel gave none).
pub fn recv_ts(sock: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddrV4, u64)> {
    let mut src: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
    let mut control = [0u64; 16]; // 128 bytes, 8-byte aligned for the cmsg headers
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = &mut src as *mut _ as *mut libc::c_void;
    msg.msg_namelen = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = mem::size_of_val(&control) as _;
    // SAFETY: every pointer in msg refers to live buffers of the stated size.
    let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut rx_ns = 0u64;
    // SAFETY: walking the control messages the kernel just wrote into `control`.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_TIMESTAMPNS {
                let ts = std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const libc::timespec);
                rx_ns = ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64;
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    if rx_ns == 0 {
        rx_ns = realtime_ns();
    }
    let addr = SocketAddrV4::new(Ipv4Addr::from(u32::from_be(src.sin_addr.s_addr)), u16::from_be(src.sin_port));
    Ok((n as usize, addr, rx_ns))
}

/// Clock probe: request "fbclkreq" + t1; reply "fbclkrep" + t1 + the
/// responder's monotonic receive and send times.
pub const CLOCK_REQ: &[u8; 8] = b"fbclkreq";
pub const CLOCK_REP: &[u8; 8] = b"fbclkrep";
