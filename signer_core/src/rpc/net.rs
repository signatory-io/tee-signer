use std::io;
use std::net::{self, UdpSocket};
use std::os::unix::{self, net::UnixDatagram};
use std::time::Duration;

pub mod vsock;

pub trait DatagramSocket {
    type Addr;
    type Error;

    fn recv(&self, buf: &mut [u8]) -> Result<usize, Self::Error>;
    fn send(&self, buf: &[u8]) -> Result<usize, Self::Error>;
    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Self::Addr), Self::Error>;
    fn send_to(&self, buf: &[u8], socket_addr: &Self::Addr) -> Result<usize, Self::Error>;
    fn set_recv_timeout(&self, timeout: Option<Duration>) -> Result<(), Self::Error>;
    fn set_send_timeout(&self, timeout: Option<Duration>) -> Result<(), Self::Error>;
}

impl DatagramSocket for UdpSocket {
    type Addr = net::SocketAddr;
    type Error = io::Error;

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Self::Addr), Self::Error> {
        self.recv_from(buf)
    }

    fn send_to(&self, buf: &[u8], socket_addr: &Self::Addr) -> Result<usize, Self::Error> {
        self.send_to(buf, socket_addr)
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.recv(buf)
    }

    fn send(&self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.send(buf)
    }

    fn set_recv_timeout(&self, timeout: Option<Duration>) -> Result<(), Self::Error> {
        self.set_read_timeout(timeout)
    }

    fn set_send_timeout(&self, timeout: Option<Duration>) -> Result<(), Self::Error> {
        self.set_write_timeout(timeout)
    }
}

impl DatagramSocket for UnixDatagram {
    type Addr = unix::net::SocketAddr;
    type Error = io::Error;

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Self::Addr), Self::Error> {
        self.recv_from(buf)
    }

    fn send_to(&self, buf: &[u8], socket_addr: &Self::Addr) -> Result<usize, Self::Error> {
        self.send_to_addr(buf, socket_addr)
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.recv(buf)
    }

    fn send(&self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.send(buf)
    }

    fn set_recv_timeout(&self, timeout: Option<Duration>) -> Result<(), Self::Error> {
        self.set_read_timeout(timeout)
    }

    fn set_send_timeout(&self, timeout: Option<Duration>) -> Result<(), Self::Error> {
        self.set_write_timeout(timeout)
    }
}
