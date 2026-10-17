//! SHAIP-GSO/1 — UDP segmentation/aggregation offload (Linux).
//!
//! A full-tunnel client sends a torrent of MTU-sized UDP datagrams. Issuing one
//! `sendmsg` syscall per datagram is a real throughput ceiling. UDP Generic
//! Segmentation Offload (GSO) lets the client hand the kernel one big buffer plus
//! a segment size in a single syscall; the kernel (or the NIC) slices it into
//! MTU-sized datagrams on the way out. Generic Receive Offload (GRO) is the
//! mirror on receive: the kernel coalesces a run of same-size datagrams into one
//! buffer the application reads in a single syscall.
//!
//! Both are plain socket options on an ordinary UDP socket — no kernel bypass, no
//! privileges — so they slot under the existing tunnel socket unchanged. This
//! module is the self-contained, tested primitive (enable GRO; send a batch with
//! GSO); the tunnel's batched-I/O path is layered on it.
//!
//! Linux only: these offloads are Linux UDP socket options. On other platforms
//! the tunnel keeps its one-datagram-per-syscall path.

use std::io;
use std::os::fd::AsRawFd;

/// `UDP_SEGMENT` (GSO): the per-send control-message / socket option carrying the
/// segment size. Not yet exported by the `libc` crate; value from `linux/udp.h`.
const UDP_SEGMENT: libc::c_int = 103;
/// `UDP_GRO`: the receive-side socket option enabling GRO coalescing. From
/// `linux/udp.h`.
const UDP_GRO: libc::c_int = 104;

/// Enable UDP GRO on a socket so the kernel may coalesce a run of equal-size
/// inbound datagrams into one read. Harmless where unsupported.
pub fn enable_gro<S: AsRawFd>(sock: &S) -> io::Result<()> {
    let on: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_UDP,
            UDP_GRO,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether this kernel accepts the GSO segment socket option at all (checked by
/// setting and clearing it on the socket). Lets callers fall back cleanly.
pub fn gso_supported<S: AsRawFd>(sock: &S) -> bool {
    let size: libc::c_int = 0; // 0 disables GSO; just probes acceptance
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_UDP,
            UDP_SEGMENT,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    rc == 0
}

/// Send `buf` as a GSO batch on a **connected** UDP socket: the kernel splits it
/// into datagrams of `segment_size` bytes (the final one may be shorter). One
/// syscall replaces up to `buf.len() / segment_size` sends.
///
/// The socket must already be `connect`ed (the tunnel's is), so no destination
/// address is passed. Returns the number of payload bytes handed to the kernel.
pub fn send_segmented<S: AsRawFd>(sock: &S, buf: &[u8], segment_size: u16) -> io::Result<usize> {
    debug_assert!(segment_size > 0);
    let fd = sock.as_raw_fd();

    let mut iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    // Control buffer for a single u16 UDP_SEGMENT control message.
    let mut cbuf = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) } as _;

    // SAFETY: msg_control points at a 64-byte buffer large enough for one u16
    // control message, and msg_controllen is set to its CMSG_SPACE above, so
    // CMSG_FIRSTHDR returns a valid, writable header.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::other("CMSG_FIRSTHDR returned null"));
        }
        (*cmsg).cmsg_level = libc::IPPROTO_UDP;
        (*cmsg).cmsg_type = UDP_SEGMENT;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut u16, segment_size);

        let n = libc::sendmsg(fd, &msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::time::Duration;

    #[test]
    fn gso_batch_is_delivered_intact() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.connect(rx_addr).unwrap();

        if !gso_supported(&tx) {
            // No GSO on this kernel — the tunnel falls back to plain sends.
            eprintln!("UDP_SEGMENT not supported here; skipping GSO assertion");
            return;
        }

        // 4 segments of 1000 bytes, each tagged with its index so we can
        // reassemble regardless of how the kernel splits/coalesces delivery.
        let seg = 1000usize;
        let segments = 4usize;
        let mut payload = vec![0u8; seg * segments];
        for (i, chunk) in payload.chunks_mut(seg).enumerate() {
            chunk.fill(i as u8);
        }

        let sent = send_segmented(&tx, &payload, seg as u16).expect("GSO send");
        assert_eq!(sent, payload.len(), "the whole batch is handed to the kernel");

        rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut got = Vec::new();
        let mut dgrams = 0;
        let mut buf = [0u8; 65536];
        while got.len() < payload.len() {
            match rx.recv(&mut buf) {
                Ok(n) => {
                    got.extend_from_slice(&buf[..n]);
                    dgrams += 1;
                }
                Err(e) => panic!("recv failed before full batch arrived: {e}"),
            }
        }
        assert_eq!(got, payload, "the reassembled batch must be byte-identical");
        // Each segment carries its index, so verify the ordering survived too.
        for (i, chunk) in got.chunks(seg).enumerate() {
            assert!(chunk.iter().all(|&b| b == i as u8), "segment {i} corrupted");
        }
        eprintln!("GSO delivered {} bytes in {dgrams} datagram(s)", got.len());
    }

    #[test]
    fn enable_gro_is_accepted_or_cleanly_unsupported() {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        match enable_gro(&sock) {
            Ok(()) => {}
            Err(e) => eprintln!("UDP_GRO unsupported here ({e}); tunnel reads one datagram at a time"),
        }
    }
}
