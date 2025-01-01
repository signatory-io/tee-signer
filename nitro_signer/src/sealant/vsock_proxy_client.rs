use aws_smithy_runtime::client::http::hyper_014::HyperClientBuilder;
pub use aws_smithy_runtime_api::client::http::SharedHttpClient;
use hyper::{
    client::connect::{Connected, Connection},
    service::Service,
    Uri,
};
use std::{future::Future, io, pin::Pin, task::Poll};
use tokio::io::{AsyncRead, AsyncWrite};

pub use vsock::asio::VSockStream;
pub use vsock::SocketAddr;

struct VSockConnection(VSockStream);

impl Connection for VSockConnection {
    fn connected(&self) -> Connected {
        Connected::new().proxy(true)
    }
}

impl AsyncRead for VSockConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for VSockConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone)]
struct VSockConnector {
    address: SocketAddr,
}

impl VSockConnector {
    pub fn new(addr: SocketAddr) -> Self {
        Self { address: addr }
    }
}

impl Service<Uri> for VSockConnector {
    type Response = VSockConnection;

    type Error = io::Error;

    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: hyper::Uri) -> Self::Future {
        let s = self.clone();
        Box::pin(async move { Ok(VSockConnection(VSockStream::connect(&s.address).await?)) })
    }
}

pub fn build(address: SocketAddr) -> SharedHttpClient {
    HyperClientBuilder::new().build(VSockConnector::new(address))
}
