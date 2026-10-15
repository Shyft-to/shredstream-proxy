//! Linux socket plumbing: batched receive (`recvmmsg`), batched send
//! (`sendmmsg`) to many destinations, socket buffers and CPU pinning.

use std::{
    io,
    mem::{size_of, zeroed},
    net::SocketAddrV4,
    os::fd::RawFd,
    ptr::null_mut,
};

/// Receive buffer per packet; larger than any datagram on a 1500-byte MTU.
const RECV_BUF: usize = 2048;

/// Linux caps one `sendmmsg` call at this many messages.
const MAX_MSGS_PER_CALL: usize = 1024;

fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn set_int_opt(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    // SAFETY: passes a valid pointer to an int of the declared size.
    check(unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const _ as *const libc::c_void,
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    })
    .map(|_| ())
}

pub fn set_recv_buffer(fd: RawFd, bytes: usize) -> io::Result<()> {
    set_int_opt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, bytes as libc::c_int)
}

pub fn set_send_buffer(fd: RawFd, bytes: usize) -> io::Result<()> {
    set_int_opt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, bytes as libc::c_int)
}

/// Pins the calling thread to one CPU.
pub fn pin_current_thread(cpu: usize) -> io::Result<()> {
    // SAFETY: cpu_set_t is plain data; CPU_SET bounds-checks `cpu`.
    unsafe {
        let mut set: libc::cpu_set_t = zeroed();
        libc::CPU_SET(cpu, &mut set);
        check(libc::sched_setaffinity(
            0,
            size_of::<libc::cpu_set_t>(),
            &set,
        ))?;
    }
    Ok(())
}

fn sockaddr(addr: &SocketAddrV4) -> libc::sockaddr_in {
    // SAFETY: sockaddr_in is plain data; all-zero is a valid value.
    let mut sa: libc::sockaddr_in = unsafe { zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_port = addr.port().to_be();
    sa.sin_addr.s_addr = u32::from_ne_bytes(addr.ip().octets());
    sa
}

/// Reusable buffers for receiving up to `capacity` datagrams in one call.
pub struct RecvBatch {
    bufs: Box<[[u8; RECV_BUF]]>,
    /// Never read directly: `msgs` point into it, so it must live as long.
    #[allow(dead_code)]
    iovecs: Box<[libc::iovec]>,
    msgs: Box<[libc::mmsghdr]>,
}

// SAFETY: the raw pointers only point into this struct's own heap buffers.
unsafe impl Send for RecvBatch {}

impl RecvBatch {
    pub fn new(capacity: usize) -> Self {
        let mut bufs: Box<[[u8; RECV_BUF]]> = vec![[0u8; RECV_BUF]; capacity].into_boxed_slice();
        let mut iovecs: Box<[libc::iovec]> = bufs
            .iter_mut()
            .map(|b| libc::iovec {
                iov_base: b.as_mut_ptr() as *mut libc::c_void,
                iov_len: RECV_BUF,
            })
            .collect();
        let msgs = iovecs
            .iter_mut()
            .map(|iov| {
                // SAFETY: mmsghdr is plain data; all-zero is valid.
                let mut m: libc::mmsghdr = unsafe { zeroed() };
                m.msg_hdr.msg_iov = iov;
                m.msg_hdr.msg_iovlen = 1;
                m
            })
            .collect();
        Self { bufs, iovecs, msgs }
    }

    /// Receives without blocking. Returns the number of datagrams (0 if none
    /// were waiting).
    pub fn recv(&mut self, fd: RawFd) -> io::Result<usize> {
        for m in self.msgs.iter_mut() {
            m.msg_hdr.msg_flags = 0;
        }
        // SAFETY: msgs/iovecs/bufs are valid for `msgs.len()` entries.
        let ret = unsafe {
            libc::recvmmsg(
                fd,
                self.msgs.as_mut_ptr(),
                self.msgs.len() as libc::c_uint,
                libc::MSG_DONTWAIT,
                null_mut(),
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            return match err.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(0),
                _ => Err(err),
            };
        }
        Ok(ret as usize)
    }

    /// The `i`-th datagram of the last `recv`, or None if it was truncated.
    pub fn packet(&self, i: usize) -> Option<&[u8]> {
        let m = &self.msgs[i];
        if m.msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
            return None;
        }
        Some(&self.bufs[i][..m.msg_len as usize])
    }
}

/// Builds and sends one `sendmmsg` batch of (packet, destination) pairs from
/// an unconnected socket.
pub struct SendBatch {
    addrs: Box<[libc::sockaddr_in]>,
    iovecs: Vec<libc::iovec>,
    /// Destination index of each queued message.
    dests: Vec<usize>,
    msgs: Vec<libc::mmsghdr>,
}

// SAFETY: pointers into `addrs` and into packets are only held between
// `push` and `send`, on the owning thread.
unsafe impl Send for SendBatch {}

impl SendBatch {
    pub fn new(dests: &[SocketAddrV4]) -> Self {
        Self {
            addrs: dests.iter().map(sockaddr).collect(),
            iovecs: Vec::with_capacity(MAX_MSGS_PER_CALL),
            dests: Vec::with_capacity(MAX_MSGS_PER_CALL),
            msgs: Vec::with_capacity(MAX_MSGS_PER_CALL),
        }
    }

    pub fn dest_count(&self) -> usize {
        self.addrs.len()
    }

    /// True when another packet for every destination would exceed one call.
    pub fn is_full(&self) -> bool {
        self.iovecs.len() + self.addrs.len() > MAX_MSGS_PER_CALL
    }

    /// Queues `packet` for destination `dest`. The packet must stay alive and
    /// unchanged until the next [`send`](Self::send).
    pub fn push(&mut self, packet: &[u8], dest: usize) {
        self.iovecs.push(libc::iovec {
            iov_base: packet.as_ptr() as *mut libc::c_void,
            iov_len: packet.len(),
        });
        self.dests.push(dest);
    }

    /// Sends everything queued. Returns (sent, failed). A message the kernel
    /// rejects is skipped and counted as failed; the rest still go out.
    pub fn send(&mut self, fd: RawFd) -> (usize, usize) {
        self.msgs.clear();
        for (iov, &dest) in self.iovecs.iter_mut().zip(&self.dests) {
            // SAFETY: mmsghdr is plain data; all-zero is valid.
            let mut m: libc::mmsghdr = unsafe { zeroed() };
            m.msg_hdr.msg_name = &mut self.addrs[dest] as *mut _ as *mut libc::c_void;
            m.msg_hdr.msg_namelen = size_of::<libc::sockaddr_in>() as libc::socklen_t;
            m.msg_hdr.msg_iov = iov;
            m.msg_hdr.msg_iovlen = 1;
            self.msgs.push(m);
        }

        let (mut sent, mut failed, mut off) = (0, 0, 0);
        while off < self.msgs.len() {
            // SAFETY: msgs[off..] point at live iovecs, addresses and packets.
            let ret = unsafe {
                libc::sendmmsg(
                    fd,
                    self.msgs[off..].as_mut_ptr(),
                    (self.msgs.len() - off) as libc::c_uint,
                    0,
                )
            };
            if ret > 0 {
                sent += ret as usize;
                off += ret as usize;
            } else if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            } else {
                // The message at `off` was rejected (e.g. unreachable); skip it.
                failed += 1;
                off += 1;
            }
        }
        self.iovecs.clear();
        self.dests.clear();
        self.msgs.clear();
        (sent, failed)
    }
}
