use aws_smithy_runtime::client::http::hyper_014::HyperClientBuilder;
pub use aws_smithy_runtime_api::client::http::SharedHttpClient;
use hyper::{
    client::connect::{Connected, Connection},
    service::Service,
    Uri,
};
use std::{future::Future, io, pin::Pin, task::Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use vsock::{asio::Stream, SocketAddr};

struct VSockConnection(Stream);

impl Connection for VSockConnection {
    fn connected(&self) -> Connected {
        Connected::new()
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
        Box::pin(async move { Ok(VSockConnection(Stream::connect(&s.address).await?)) })
    }
}

pub fn build(address: SocketAddr) -> SharedHttpClient {
    use hyper_rustls::ConfigBuilderExt;

    // copied from aws_smithy_runtime::client::http::hyper_014 except for the cert roots
    let cc = rustls::ClientConfig::builder()
        .with_cipher_suites(&[
            // TLS1.3 suites
            rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
            rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
            // TLS1.2 suites
            rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ])
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .expect("Error with the TLS configuration")
        .with_webpki_roots()
        .with_no_client_auth();

    let vsock_connector = VSockConnector::new(address);

    let https_connector = hyper_rustls::HttpsConnector::from((vsock_connector, cc));
    HyperClientBuilder::new().build(https_connector)
}
