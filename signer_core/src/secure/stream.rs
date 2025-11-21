use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use super::Session;

pub struct EncryptedStream<T> {
    inner: T,
    session: Session,
    read_buffer: Vec<u8>,
    read_pos: usize,
    write_buffer: Option<Vec<u8>>,
}

impl<T> EncryptedStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(inner: T, session: Session) -> Self {
        Self {
            inner,
            session,
            read_buffer: Vec::new(),
            read_pos: 0,
            write_buffer: None,
        }
    }

    async fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        let mut enc_len_buf = [0u8; 4];
        self.inner.read_exact(&mut enc_len_buf).await?;

        let payload_len = self
            .session
            .decrypt_length(&enc_len_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let mut payload = vec![0u8; payload_len];
        self.inner.read_exact(&mut payload).await?;

        let mut packet = Vec::with_capacity(4 + payload_len);
        packet.extend_from_slice(&enc_len_buf);
        packet.extend_from_slice(&payload);

        self.session
            .read_packet(&packet)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

impl<T> AsyncRead for EncryptedStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.read_pos < this.read_buffer.len() {
            let remaining = &this.read_buffer[this.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            this.read_pos += to_copy;

            if this.read_pos >= this.read_buffer.len() {
                this.read_buffer.clear();
                this.read_pos = 0;
            }

            return Poll::Ready(Ok(()));
        }

        struct ReadFuture<'a, T: AsyncRead + AsyncWrite + Unpin> {
            stream: &'a mut EncryptedStream<T>,
        }

        impl<'a, T: AsyncRead + AsyncWrite + Unpin> Future for ReadFuture<'a, T> {
            type Output = io::Result<Vec<u8>>;

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let fut = self.stream.read_packet();
                tokio::pin!(fut);
                fut.poll(cx)
            }
        }

        let mut read_fut = ReadFuture { stream: this };

        match Pin::new(&mut read_fut).poll(cx) {
            Poll::Ready(Ok(plaintext)) => {
                let plaintext_len = plaintext.len();
                let to_copy = plaintext_len.min(buf.remaining());

                buf.put_slice(&plaintext[..to_copy]);

                if to_copy < plaintext_len {
                    read_fut.stream.read_buffer = plaintext[to_copy..].to_vec();
                    read_fut.stream.read_pos = 0;
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T> AsyncWrite for EncryptedStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.write_buffer.is_none() {
            match this.session.write_packet(buf) {
                Ok(packet) => {
                    this.write_buffer = Some(packet);
                }
                Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e))),
            }
        }

        if let Some(packet) = &this.write_buffer {
            let write_buf = packet.as_slice();
            match Pin::new(&mut this.inner).poll_write(cx, write_buf) {
                Poll::Ready(Ok(n)) => {
                    if n == packet.len() {
                        this.write_buffer = None;
                        Poll::Ready(Ok(buf.len()))
                    } else {
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "partial packet write",
                        )))
                    }
                }
                Poll::Ready(Err(e)) => {
                    this.write_buffer = None;
                    Poll::Ready(Err(e))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            unreachable!("write_buffer should be Some after initialization")
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

    async fn create_test_sessions() -> (Session, Session) {
        let mut session1 = Session::new();
        let mut session2 = Session::new();

        let secret = [1u8; 32];
        let local = [2u8; 32];
        let remote = [3u8; 32];

        session1.derive_keys(&secret, &local, &remote).unwrap();
        session2.derive_keys(&secret, &remote, &local).unwrap();

        (session1, session2)
    }

    #[tokio::test]
    async fn test_encrypted_stream_read_write() {
        let (stream1, stream2) = UnixStream::pair().unwrap();
        let (session1, session2) = create_test_sessions().await;

        let mut enc_stream1 = EncryptedStream::new(stream1, session1);
        let mut enc_stream2 = EncryptedStream::new(stream2, session2);

        let message = b"Hello, encrypted world!";

        enc_stream1.write_all(message).await.unwrap();

        let mut buf = vec![0u8; 4 + message.len()];
        enc_stream2.read_exact(&mut buf).await.unwrap();

        let length = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
        assert_eq!(length, message.len());
        assert_eq!(message, &buf[4..]);
    }

    #[tokio::test]
    async fn test_encrypted_stream_bidirectional() {
        let (stream1, stream2) = UnixStream::pair().unwrap();
        let (session1, session2) = create_test_sessions().await;

        let mut enc_stream1 = EncryptedStream::new(stream1, session1);
        let mut enc_stream2 = EncryptedStream::new(stream2, session2);

        let msg1 = b"From 1 to 2";
        enc_stream1.write_all(msg1).await.unwrap();
        let mut buf1 = vec![0u8; 4 + msg1.len()];
        enc_stream2.read_exact(&mut buf1).await.unwrap();
        assert_eq!(msg1, &buf1[4..]);

        let msg2 = b"From 2 to 1";
        enc_stream2.write_all(msg2).await.unwrap();
        let mut buf2 = vec![0u8; 4 + msg2.len()];
        enc_stream1.read_exact(&mut buf2).await.unwrap();
        assert_eq!(msg2, &buf2[4..]);
    }

    #[tokio::test]
    async fn test_encrypted_stream_large_message() {
        let (stream1, stream2) = UnixStream::pair().unwrap();
        let (session1, session2) = create_test_sessions().await;

        let mut enc_stream1 = EncryptedStream::new(stream1, session1);
        let mut enc_stream2 = EncryptedStream::new(stream2, session2);

        // Large message (multiple packets)
        let large_msg = vec![42u8; 10000];

        enc_stream1.write_all(&large_msg).await.unwrap();
        let mut buf = vec![0u8; 4 + large_msg.len()];
        enc_stream2.read_exact(&mut buf).await.unwrap();

        let length = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
        assert_eq!(length, large_msg.len());
        assert_eq!(large_msg, &buf[4..]);
    }
}
