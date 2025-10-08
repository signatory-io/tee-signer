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

#[cfg(test)]
mod tests {
    use std::task::Waker;

    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use vsock::{asio::Listener, VMADDR_CID_ANY, VMADDR_CID_LOCAL, VMADDR_PORT_ANY};

    #[test]
    fn test_vsock_connector_new() {
        let addr = SocketAddr::new(3, 8000);
        let connector = VSockConnector::new(addr);
        assert_eq!(connector.address.cid(), 3);
        assert_eq!(connector.address.port(), 8000);
    }

    #[test]
    fn test_build_creates_client() {
        let addr = SocketAddr::new(3, 8000);
        let _client = build(addr);
        // Test passes if build doesn't panic
    }

    #[tokio::test]
    async fn test_vsock_connector_and_connection() {
        // Start a server on any available port
        let listener = Listener::bind(&SocketAddr::new(VMADDR_CID_ANY, VMADDR_PORT_ANY)).unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Test data to send
        let test_data = b"Hello VSock!";

        // Run server and client concurrently
        tokio::join!(
            // Server task
            async {
                let (mut conn, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 1024];
                let n = conn.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], test_data);
                conn.write_all(b"Echo: ").await.unwrap();
                conn.write_all(&buf[..n]).await.unwrap();
            },
            // Client task
            async {
                let addr = SocketAddr::new(VMADDR_CID_LOCAL, server_addr.port());
                let mut connector = VSockConnector::new(addr);
                assert!(connector
                    .poll_ready(&mut std::task::Context::from_waker(&Waker::noop()))
                    .is_ready());

                // Use connector to establish connection via hyper Service trait
                use hyper::service::Service;
                let mut connection = connector.call(Uri::default()).await.unwrap();

                connection.connected();

                // Write test data
                connection.write_all(test_data).await.unwrap();

                // Pin the connection for poll_* methods
                let mut pinned = Pin::new(&mut connection);
                assert!(pinned
                    .as_mut()
                    .poll_flush(&mut std::task::Context::from_waker(&Waker::noop()))
                    .is_ready());
                assert!(pinned
                    .as_mut()
                    .poll_shutdown(&mut std::task::Context::from_waker(&Waker::noop()))
                    .is_ready());

                // Read echo response
                let mut buf = [0u8; 64];
                let n = connection.read(&mut buf).await.unwrap();

                let expected = format!("Echo: {}", String::from_utf8_lossy(test_data));
                assert_eq!(&expected.as_bytes()[..n], &buf[..n]);
            }
        );
    }
}
