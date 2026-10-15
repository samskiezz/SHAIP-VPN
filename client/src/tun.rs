//! Linux TUN device binding (§19 data plane).
//!
//! Opens `/dev/net/tun`, creates an `IFF_TUN | IFF_NO_PI` layer-3 interface, and
//! exposes blocking read/write of raw IP packets. This is the only module that
//! touches the kernel through libc FFI; the cryptographic core stays safe Rust.
//! Async drivers wrap [`TunDevice`] in tokio's `AsyncFd` (see the daemons).
//!
//! Linux only — TUN is a Linux kernel interface. On other platforms the module
//! is absent and callers get a compile-time `cfg` gate.

use std::ffi::CString;
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

// _IOW('T', 202, int) on Linux.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFNAMSIZ: usize = 16;

// Interface-configuration ioctls (operate on an AF_INET socket, by name).
const SIOCSIFADDR: libc::c_ulong = 0x8916;
const SIOCSIFNETMASK: libc::c_ulong = 0x891c;
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;

#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; IFNAMSIZ],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

/// An open TUN device carrying raw IP packets.
pub struct TunDevice {
    fd: OwnedFd,
    name: String,
}

impl TunDevice {
    /// Open (creating if needed) a TUN device. `requested` is a desired name
    /// such as `"pqanon0"`; the kernel may hand back the next free name, which
    /// [`name`](TunDevice::name) reports. Requires `CAP_NET_ADMIN`.
    pub fn open(requested: &str) -> io::Result<Self> {
        let path = CString::new("/dev/net/tun").expect("static path has no NUL");
        // SAFETY: opening a device node with a valid, NUL-terminated C path.
        let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a freshly-opened fd we now solely own.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // SAFETY: IfReq is a plain-old-data struct; zeroing is a valid state.
        let mut req: IfReq = unsafe { std::mem::zeroed() };
        let name_bytes = requested.as_bytes();
        if name_bytes.len() >= IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tun name too long",
            ));
        }
        for (slot, &b) in req.ifr_name.iter_mut().zip(name_bytes) {
            *slot = b as libc::c_char;
        }
        req.ifr_flags = IFF_TUN | IFF_NO_PI;

        // SAFETY: `fd` is a valid TUN control fd and `req` is a correctly-sized
        // ifreq that the kernel reads and writes in place.
        let ret = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &mut req as *mut IfReq) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            name: ifr_name_to_string(&req.ifr_name),
            fd,
        })
    }

    /// The interface name the kernel assigned.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Assign an IPv4 address + prefix and bring the interface up, entirely via
    /// ioctls (no dependency on the `ip`/`ifconfig` binaries). This installs the
    /// connected route for the subnet so the kernel sends matching traffic out
    /// this device. Requires `CAP_NET_ADMIN`.
    pub fn configure_v4(&self, addr: Ipv4Addr, prefix: u8) -> io::Result<()> {
        // SAFETY: creating an AF_INET datagram socket; args are plain ints.
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: freshly-opened fd we own.
        let sock = unsafe { OwnedFd::from_raw_fd(raw) };
        let s = sock.as_raw_fd();

        set_ifaddr(s, &self.name, SIOCSIFADDR, addr)?;
        set_ifaddr(s, &self.name, SIOCSIFNETMASK, prefix_to_mask(prefix))?;
        set_if_up(s, &self.name)?;
        Ok(())
    }

    /// Switch the device to non-blocking mode (required by async drivers).
    pub fn set_nonblocking(&self) -> io::Result<()> {
        let fd = self.fd.as_raw_fd();
        // SAFETY: F_GETFL/F_SETFL on a valid fd take no pointer arguments.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: as above; setting the O_NONBLOCK bit.
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Read one IP packet into `buf`, returning its length.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: writing at most `buf.len()` bytes into `buf` via a valid fd.
        let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// Write one IP packet.
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: reading exactly `buf.len()` bytes from `buf` via a valid fd.
        let n = unsafe { libc::write(self.fd.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

impl AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Async wrapper over a [`TunDevice`] for tokio drivers. Registers the device's
/// fd with the reactor and exposes `recv`/`send` of whole IP packets.
pub struct AsyncTun {
    inner: tokio::io::unix::AsyncFd<TunDevice>,
}

impl AsyncTun {
    /// Wrap a device, switching it to non-blocking mode.
    pub fn new(dev: TunDevice) -> io::Result<Self> {
        dev.set_nonblocking()?;
        // SAFETY: `dev` owns its fd via `OwnedFd` and keeps it open and valid
        // for as long as the returned `AsyncFd` holds it — the contract
        // `register` requires (the fd must outlive the registration).
        let inner = match unsafe { tokio::io::unix::AsyncFd::register(dev) } {
            Ok(inner) => inner,
            Err(_) => {
                return Err(io::Error::other(
                    "failed to register TUN fd with the tokio reactor",
                ))
            }
        };
        Ok(Self { inner })
    }

    pub fn name(&self) -> &str {
        self.inner.get_ref().name()
    }

    /// Read one IP packet, awaiting readiness.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|d| d.get_ref().read(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Write one IP packet, awaiting writability.
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|d| d.get_ref().write(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

fn ifr_name_to_string(name: &[libc::c_char; IFNAMSIZ]) -> String {
    let bytes: Vec<u8> = name
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn prefix_to_mask(prefix: u8) -> Ipv4Addr {
    let bits: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32))
    };
    Ipv4Addr::from(bits)
}

fn copy_name(dst: &mut [libc::c_char; IFNAMSIZ], name: &str) -> io::Result<()> {
    let b = name.as_bytes();
    if b.len() >= IFNAMSIZ {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "ifname too long"));
    }
    for (slot, &byte) in dst.iter_mut().zip(b) {
        *slot = byte as libc::c_char;
    }
    Ok(())
}

/// Set an IPv4 address-shaped field (address or netmask) on an interface.
fn set_ifaddr(sock: RawFd, name: &str, request: libc::c_ulong, ip: Ipv4Addr) -> io::Result<()> {
    #[repr(C)]
    struct IfReqAddr {
        ifr_name: [libc::c_char; IFNAMSIZ],
        ifr_addr: libc::sockaddr,
    }
    // SAFETY: POD struct; zeroing is valid.
    let mut req: IfReqAddr = unsafe { std::mem::zeroed() };
    copy_name(&mut req.ifr_name, name)?;

    // SAFETY: sockaddr_in is POD.
    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(ip.octets()),
    };
    // sockaddr_in and sockaddr are both 16 bytes on Linux; copy the bytes in.
    // SAFETY: copying size_of::<sockaddr>() bytes between two POD values of
    // equal size.
    unsafe {
        std::ptr::copy_nonoverlapping(
            std::ptr::addr_of!(sin).cast::<u8>(),
            std::ptr::addr_of_mut!(req.ifr_addr).cast::<u8>(),
            std::mem::size_of::<libc::sockaddr>(),
        );
    }

    // SAFETY: valid socket fd and correctly-shaped ifreq for the SIOCSIF* call.
    if unsafe { libc::ioctl(sock, request, &mut req as *mut IfReqAddr) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Bring an interface up (IFF_UP | IFF_RUNNING).
fn set_if_up(sock: RawFd, name: &str) -> io::Result<()> {
    #[repr(C)]
    struct IfReqFlags {
        ifr_name: [libc::c_char; IFNAMSIZ],
        ifr_flags: libc::c_short,
        _pad: [u8; 22],
    }
    // SAFETY: POD struct; zeroing is valid.
    let mut req: IfReqFlags = unsafe { std::mem::zeroed() };
    copy_name(&mut req.ifr_name, name)?;

    // SAFETY: read current flags into req.
    if unsafe { libc::ioctl(sock, SIOCGIFFLAGS, &mut req as *mut IfReqFlags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    req.ifr_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    // SAFETY: write the updated flags back.
    if unsafe { libc::ioctl(sock, SIOCSIFFLAGS, &mut req as *mut IfReqFlags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
