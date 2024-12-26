use crate::rpc::net::DatagramSocket;
use libc::AF_VSOCK;
pub use libc::{
    VMADDR_CID_ANY, VMADDR_CID_HOST, VMADDR_CID_HYPERVISOR, VMADDR_CID_RESERVED, VMADDR_PORT_ANY,
};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::{io, mem};

pub struct SocketAddr(libc::sockaddr_vm);

impl SocketAddr {
    pub fn new(cid: u32, port: u32) -> Self {
        let mut sa: libc::sockaddr_vm = unsafe { mem::zeroed() };
        sa.svm_family = libc::AF_VSOCK as u8;
        sa.svm_port = port;
        sa.svm_cid = cid;
        SocketAddr(sa)
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

pub struct VSockDatagram(OwnedFd);

fn libc_ret<T: num::Signed>(v: T) -> Result<T, io::Error> {
    if v.is_negative() {
        Err(io::Error::last_os_error())
    } else {
        Ok(v)
    }
}

impl VSockDatagram {
    unsafe fn socket() -> Result<OwnedFd, io::Error> {
        let fd = libc_ret(libc::socket(libc::AF_VSOCK, libc::SOCK_DGRAM, 0))?;
        let flags = libc_ret(libc::fcntl(fd, libc::F_GETFD, 0))?;
        libc_ret(libc::fcntl(fd, libc::F_SETFD, flags))?;
        Ok(OwnedFd::from_raw_fd(fd))
    }

    pub fn bind(addr: &SocketAddr) -> Result<Self, io::Error> {
        unsafe {
            let fd = Self::socket()?;
            libc_ret(libc::bind(
                fd.as_raw_fd(),
                &addr.0 as *const libc::sockaddr_vm as *const libc::sockaddr,
                size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            ))
            .and(Ok(VSockDatagram(fd)))
        }
    }

    pub fn connect(addr: &SocketAddr) -> Result<Self, io::Error> {
        unsafe {
            let fd = Self::socket()?;
            libc_ret(libc::connect(
                fd.as_raw_fd(),
                &addr.0 as *const libc::sockaddr_vm as *const libc::sockaddr,
                size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            ))
            .and(Ok(VSockDatagram(fd)))
        }
    }

    fn set_timeout(
        &self,
        name: libc::c_int,
        timeout: Option<std::time::Duration>,
    ) -> Result<(), io::Error> {
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
        libc_ret(unsafe {
            libc::setsockopt(
                self.0.as_raw_fd(),
                libc::SOL_SOCKET,
                name,
                &tv as *const libc::timeval as *const libc::c_void,
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        })
        .and(Ok(()))
    }
}

impl DatagramSocket for VSockDatagram {
    type Addr = SocketAddr;
    type Error = io::Error;

    fn recv(&self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        libc_ret(unsafe {
            libc::recv(
                self.0.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        })
        .map(|x| x as usize)
    }

    fn send(&self, buf: &[u8]) -> Result<usize, Self::Error> {
        libc_ret(unsafe {
            libc::send(
                self.0.as_raw_fd(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
            )
        })
        .map(|x| x as usize)
    }

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Self::Addr), Self::Error> {
        let (len, addr) = unsafe {
            let mut addr = SocketAddr(mem::zeroed());
            let mut addr_len = size_of::<libc::sockaddr_vm>() as libc::socklen_t;

            let len = libc_ret(libc::recvfrom(
                self.0.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut addr.0 as *mut libc::sockaddr_vm as *mut libc::sockaddr,
                &mut addr_len as *mut libc::socklen_t,
            ))?;
            (len, addr)
        };

        if addr.0.svm_family != AF_VSOCK as u8 {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file descriptor did not correspond to a AF_VSOCK",
            ))
        } else {
            Ok((len as usize, addr))
        }
    }

    fn send_to(&self, buf: &[u8], addr: &Self::Addr) -> Result<usize, Self::Error> {
        libc_ret(unsafe {
            libc::sendto(
                self.0.as_raw_fd(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
                &addr.0 as *const libc::sockaddr_vm as *const libc::sockaddr,
                size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        })
        .map(|x| x as usize)
    }

    fn set_recv_timeout(&self, timeout: Option<std::time::Duration>) -> Result<(), Self::Error> {
        self.set_timeout(libc::SO_RCVTIMEO, timeout)
    }

    fn set_send_timeout(&self, timeout: Option<std::time::Duration>) -> Result<(), Self::Error> {
        self.set_timeout(libc::SO_SNDTIMEO, timeout)
    }
}
