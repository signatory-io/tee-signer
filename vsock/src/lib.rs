use libc::AF_VSOCK;
pub use libc::{VMADDR_CID_ANY, VMADDR_CID_HOST, VMADDR_CID_HYPERVISOR, VMADDR_PORT_ANY};
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::mem::zeroed;
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

pub mod asio;
mod utils;

use utils::{
    accept, bind, connect, fcntl, getpeername, getsockname, getsockopt, libc_ret, listen, recv,
    recvfrom, send, sendto, setsockopt, shutdown, socket,
};

pub const VMADDR_CID_LOCAL: libc::c_uint = 1;

pub struct SocketAddr(libc::sockaddr_vm);

impl SocketAddr {
    pub fn new(cid: u32, port: u32) -> Self {
        let mut sa: libc::sockaddr_vm = unsafe { zeroed() };
        sa.svm_family = AF_VSOCK.try_into().unwrap();
        sa.svm_port = port;
        sa.svm_cid = cid;
        Self(sa)
    }

    pub const fn port(&self) -> u32 {
        self.0.svm_port
    }

    pub const fn cid(&self) -> u32 {
        self.0.svm_cid
    }
}

impl std::fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.cid(), self.port())
    }
}

impl std::fmt::Debug for SocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "vsock:{}:{}", self.cid(), self.port())
    }
}

pub fn local_cid() -> Result<u32> {
    const DEV: &std::ffi::CStr = c"/dev/vsock";
    const IOCTL_VM_SOCKETS_GET_LOCAL_CID: libc::c_ulong = 0x7b9;

    let mut cid = 0_u32;
    unsafe {
        let fd = OwnedFd::from_raw_fd(libc_ret(libc::open(DEV.as_ptr(), libc::O_RDONLY))?);
        libc_ret(libc::ioctl(
            fd.as_raw_fd(),
            IOCTL_VM_SOCKETS_GET_LOCAL_CID,
            &mut cid as *mut u32,
        ))
    }
    .and(Ok(cid))
}

struct Inner(OwnedFd);

impl Inner {
    fn socket(ty: libc::c_int) -> Result<OwnedFd> {
        let fd = socket(libc::AF_VSOCK, ty, 0)?;
        let flags = fcntl(fd.as_raw_fd(), libc::F_GETFD, 0)?;
        fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC)?;
        Ok(fd)
    }

    fn unbound(ty: libc::c_int) -> Result<Self> {
        Ok(Self(Self::socket(ty)?))
    }

    fn bind(ty: libc::c_int, addr: &SocketAddr) -> Result<Self> {
        let fd = Self::socket(ty)?;
        bind(fd.as_raw_fd(), &addr.0).and(Ok(Self(fd)))
    }

    fn connect(&self, addr: &SocketAddr) -> Result<()> {
        connect(self.0.as_raw_fd(), &addr.0)
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        let addr: libc::sockaddr_vm = getsockname(self.0.as_raw_fd())?;
        if addr.svm_family as libc::c_int != AF_VSOCK {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "file descriptor did not correspond to a AF_VSOCK",
            ))
        } else {
            Ok(SocketAddr(addr))
        }
    }

    fn peer_addr(&self) -> Result<SocketAddr> {
        let addr: libc::sockaddr_vm = getpeername(self.0.as_raw_fd())?;
        if addr.svm_family as libc::c_int != AF_VSOCK {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "file descriptor did not correspond to a AF_VSOCK",
            ))
        } else {
            Ok(SocketAddr(addr))
        }
    }

    fn set_timeout(&self, name: libc::c_int, timeout: Option<std::time::Duration>) -> Result<()> {
        let tv = match timeout {
            Some(val) => libc::timeval {
                tv_sec: val.as_secs() as libc::time_t,
                tv_usec: val.subsec_micros() as libc::suseconds_t,
            },
            None => libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
        };
        setsockopt(self.0.as_raw_fd(), libc::SOL_SOCKET, name, &tv)
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        recv(self.0.as_raw_fd(), buf)
    }

    fn send(&self, buf: &[u8]) -> Result<usize> {
        send(self.0.as_raw_fd(), buf)
    }

    fn set_recv_timeout(&self, timeout: Option<std::time::Duration>) -> Result<()> {
        self.set_timeout(libc::SO_RCVTIMEO, timeout)
    }

    fn set_send_timeout(&self, timeout: Option<std::time::Duration>) -> Result<()> {
        self.set_timeout(libc::SO_SNDTIMEO, timeout)
    }

    fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        let flags = fcntl(self.0.as_raw_fd(), libc::F_GETFL, 0)?;
        fcntl(
            self.0.as_raw_fd(),
            libc::F_SETFL,
            if nonblocking {
                flags | libc::O_NONBLOCK
            } else {
                flags & !libc::O_NONBLOCK
            },
        )
        .and(Ok(()))
    }

    fn shutdown(&self, how: Shutdown) -> Result<()> {
        shutdown(
            self.0.as_raw_fd(),
            match how {
                Shutdown::Read => libc::SHUT_RD,
                Shutdown::Write => libc::SHUT_WR,
                Shutdown::Both => libc::SHUT_RDWR,
            },
        )
    }

    fn take_error(&self) -> Result<Option<Error>> {
        let err: libc::c_int = getsockopt(self.0.as_raw_fd(), libc::SOL_SOCKET, libc::SO_ERROR)?;
        Ok(if err == 0 {
            None
        } else {
            Some(Error::from_raw_os_error(err))
        })
    }
}

impl AsRawFd for Inner {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl AsFd for Inner {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

pub struct Datagram(Inner);

impl Datagram {
    pub fn unbound() -> Result<Self> {
        Ok(Self(Inner::unbound(libc::SOCK_DGRAM)?))
    }

    pub fn bind(addr: &SocketAddr) -> Result<Self> {
        Ok(Self(Inner::bind(libc::SOCK_DGRAM, addr)?))
    }

    pub fn connect(&self, addr: &SocketAddr) -> Result<()> {
        self.0.connect(addr)
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.0.local_addr()
    }

    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.0.peer_addr()
    }

    pub fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        self.0.recv(buf)
    }

    pub fn send(&self, buf: &[u8]) -> Result<usize> {
        self.0.send(buf)
    }

    pub fn set_recv_timeout(&self, timeout: Option<std::time::Duration>) -> Result<()> {
        self.0.set_recv_timeout(timeout)
    }

    pub fn set_send_timeout(&self, timeout: Option<std::time::Duration>) -> Result<()> {
        self.0.set_send_timeout(timeout)
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (len, addr) = recvfrom::<libc::sockaddr_vm>(self.as_raw_fd(), buf, 0)?;
        if addr.svm_family as libc::c_int != AF_VSOCK {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "file descriptor did not correspond to a AF_VSOCK",
            ))
        } else {
            Ok((len, SocketAddr(addr)))
        }
    }

    pub fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        sendto(self.as_raw_fd(), buf, 0, &addr.0)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    pub fn shutdown(&self, how: Shutdown) -> Result<()> {
        self.0.shutdown(how)
    }

    pub fn take_error(&self) -> Result<Option<Error>> {
        self.0.take_error()
    }
}

impl Write for Datagram {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.0.send(buf)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<'a> Write for &'a Datagram {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.0.send(buf)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Read for Datagram {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.0.recv(buf)
    }
}

impl AsFd for Datagram {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for Datagram {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

pub struct Stream(Inner);

impl Stream {
    fn unbound() -> Result<Self> {
        Ok(Self(Inner::unbound(libc::SOCK_STREAM)?))
    }

    fn connect_to_addr(&self, addr: &SocketAddr) -> Result<()> {
        self.0.connect(addr)
    }

    pub fn connect(addr: &SocketAddr) -> Result<Self> {
        let sock = Stream::unbound()?;
        sock.connect_to_addr(addr)?;
        Ok(sock)
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.0.local_addr()
    }

    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.0.peer_addr()
    }

    pub fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        self.0.recv(buf)
    }

    pub fn send(&self, buf: &[u8]) -> Result<usize> {
        self.0.send(buf)
    }

    pub fn set_recv_timeout(&self, timeout: Option<std::time::Duration>) -> Result<()> {
        self.0.set_recv_timeout(timeout)
    }

    pub fn set_send_timeout(&self, timeout: Option<std::time::Duration>) -> Result<()> {
        self.0.set_send_timeout(timeout)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    pub fn shutdown(&self, how: Shutdown) -> Result<()> {
        self.0.shutdown(how)
    }

    pub fn take_error(&self) -> Result<Option<Error>> {
        self.0.take_error()
    }
}

impl AsRef<Inner> for Datagram {
    fn as_ref(&self) -> &Inner {
        &self.0
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.0.send(buf)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<'a> Write for &'a Stream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.0.send(buf)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.0.recv(buf)
    }
}

impl AsFd for Stream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for Stream {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

pub struct Listener(Inner);

impl Listener {
    pub fn bind(addr: &SocketAddr) -> Result<Self> {
        let inner = Inner::bind(libc::SOCK_STREAM, addr)?;
        listen(inner.as_raw_fd(), libc::SOMAXCONN)?;
        Ok(Self(inner))
    }

    pub fn accept(&self) -> Result<(Stream, SocketAddr)> {
        let (fd, addr) = accept::<libc::sockaddr_vm>(self.as_raw_fd())?;
        Ok((Stream(Inner(fd)), SocketAddr(addr)))
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.0.local_addr()
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    pub fn take_error(&self) -> Result<Option<Error>> {
        self.0.take_error()
    }

    pub fn incoming(&self) -> Incoming {
        Incoming(self)
    }
}

impl AsFd for Listener {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for Listener {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl<'a> IntoIterator for &'a Listener {
    type Item = Result<Stream>;
    type IntoIter = Incoming<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.incoming()
    }
}

pub struct Incoming<'a>(&'a Listener);

impl<'a> Iterator for Incoming<'a> {
    type Item = Result<Stream>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.0.accept().map(|pair| pair.0))
    }
}

#[cfg(test)]
mod tests {
    use super::asio::{VSockListener, VSockStream};
    use super::{Listener, SocketAddr, Stream, VMADDR_CID_ANY, VMADDR_CID_LOCAL};
    use std::thread;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn echo() {
        let listener = Listener::bind(&SocketAddr::new(VMADDR_CID_ANY, 3000)).unwrap();
        let jh = thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            let mut buf: [u8; 8] = [0; 8];
            conn.recv(&mut buf).unwrap();
            conn.send(&buf).unwrap();
        });

        let data: &[u8; 8] = b"datadata";

        let client = Stream::connect(&SocketAddr::new(VMADDR_CID_LOCAL, 3000)).unwrap();
        client.send(data).unwrap();

        let mut buf: [u8; 1024] = [0; 1024];
        let sz = client.recv(&mut buf).unwrap();
        assert_eq!(&buf[0..sz], data);
        jh.join().unwrap();
    }

    #[tokio::test]
    async fn async_echo() {
        let listener = VSockListener::bind(&SocketAddr::new(VMADDR_CID_ANY, 3001)).unwrap();
        futures::join!(
            async {
                let (conn, _) = listener.accept().await.unwrap();
                let mut buf: [u8; 8] = [0; 8];
                conn.recv(&mut buf).await.unwrap();
                conn.send(&buf).await.unwrap();
            },
            async {
                let data: &[u8; 8] = b"datadata";
                let client = VSockStream::connect(&SocketAddr::new(VMADDR_CID_LOCAL, 3001))
                    .await
                    .unwrap();
                client.send(data).await.unwrap();
                let mut buf: [u8; 1024] = [0; 1024];
                let sz = client.recv(&mut buf).await.unwrap();
                assert_eq!(&buf[0..sz], data);
            }
        );
    }

    #[tokio::test]
    async fn async_echo_poll() {
        let listener = VSockListener::bind(&SocketAddr::new(VMADDR_CID_ANY, 3001)).unwrap();
        futures::join!(
            async {
                let (mut conn, _) = std::future::poll_fn(|cx| listener.poll_accept(cx))
                    .await
                    .unwrap();

                let mut buf: [u8; 8] = [0; 8];
                conn.read_exact(&mut buf).await.unwrap();
                conn.write(&buf).await.unwrap();
            },
            async {
                let data: &[u8; 8] = b"datadata";
                let mut client = VSockStream::connect(&SocketAddr::new(VMADDR_CID_LOCAL, 3001))
                    .await
                    .unwrap();
                client.write(data).await.unwrap();
                let mut buf: [u8; 1024] = [0; 1024];
                let sz = client.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf[0..sz], data);
            }
        );
    }
}
