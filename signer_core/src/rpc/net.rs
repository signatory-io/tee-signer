use std::future::Future;
use std::io::{Error, ErrorKind};
use std::os::unix::{self, net::UnixDatagram};
use vsock::asio::VSockDatagram;

pub trait Socket {
    type Addr: std::fmt::Debug;
    type Error;
}

pub trait DatagramSocket: Socket {
    fn recv(&self, buf: &mut [u8]) -> Result<usize, Self::Error>;
    fn send(&self, buf: &[u8]) -> Result<usize, Self::Error>;
    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Self::Addr), Self::Error>;
    fn send_to(&self, buf: &[u8], socket_addr: &Self::Addr) -> Result<usize, Self::Error>;
}

impl Socket for UnixDatagram {
    type Addr = unix::net::SocketAddr;
    type Error = Error;
}

impl DatagramSocket for UnixDatagram {
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
}

impl Socket for vsock::Datagram {
    type Addr = vsock::SocketAddr;
    type Error = Error;
}

impl DatagramSocket for vsock::Datagram {
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
}

pub trait AsyncDatagramSocket: Socket {
    fn recv(&self, buf: &mut [u8]) -> impl Future<Output = Result<usize, Self::Error>> + Send;
    fn send(&self, buf: &[u8]) -> impl Future<Output = Result<usize, Self::Error>> + Send;
    fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<(usize, Self::Addr), Self::Error>> + Send;
    fn send_to(
        &self,
        buf: &[u8],
        socket_addr: &Self::Addr,
    ) -> impl Future<Output = Result<usize, Self::Error>> + Send;
}

impl Socket for VSockDatagram {
    type Addr = vsock::SocketAddr;
    type Error = Error;
}

impl AsyncDatagramSocket for VSockDatagram {
    async fn recv(&self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.recv(buf).await
    }

    async fn send(&self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.send(buf).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Self::Addr), Self::Error> {
        self.recv_from(buf).await
    }

    async fn send_to(&self, buf: &[u8], addr: &Self::Addr) -> Result<usize, Self::Error> {
        self.send_to(buf, addr).await
    }
}

impl Socket for tokio::net::UnixDatagram {
    type Addr = tokio::net::unix::SocketAddr;
    type Error = Error;
}

impl AsyncDatagramSocket for tokio::net::UnixDatagram {
    async fn recv(&self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.recv(buf).await
    }

    async fn send(&self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.send(buf).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Self::Addr), Self::Error> {
        self.recv_from(buf).await
    }

    async fn send_to(&self, buf: &[u8], addr: &Self::Addr) -> Result<usize, Self::Error> {
        match addr.as_pathname() {
            Some(path) => self.send_to(buf, path).await,
            None => Err(Error::new(ErrorKind::InvalidInput, "unnamed")),
        }
    }
}
