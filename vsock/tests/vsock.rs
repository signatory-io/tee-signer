#[cfg(target_os = "linux")]
mod linux {
    use std::thread;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use vsock::asio::{Listener, Stream};
    use vsock::{
        Listener as SyncListener, SocketAddr, Stream as SyncStream, VMADDR_CID_ANY,
        VMADDR_CID_LOCAL, VMADDR_PORT_ANY,
    };

    #[test]
    fn echo() {
        let listener =
            SyncListener::bind(&SocketAddr::new(VMADDR_CID_ANY, VMADDR_PORT_ANY)).unwrap();
        let loc = listener.local_addr().unwrap();
        let jh = thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            let mut buf: [u8; 8] = [0; 8];
            conn.recv(&mut buf).unwrap();
            conn.send(&buf).unwrap();
        });

        let data: &[u8; 8] = b"datadata";

        let client = SyncStream::connect(&SocketAddr::new(VMADDR_CID_LOCAL, loc.port())).unwrap();
        client.send(data).unwrap();

        let mut buf: [u8; 1024] = [0; 1024];
        let sz = client.recv(&mut buf).unwrap();
        assert_eq!(&buf[0..sz], data);
        jh.join().unwrap();
    }

    #[test]
    fn echo_iter() {
        let listener =
            SyncListener::bind(&SocketAddr::new(VMADDR_CID_ANY, VMADDR_PORT_ANY)).unwrap();
        let loc = listener.local_addr().unwrap();
        let jh = thread::spawn(move || {
            let mut count = 0;
            for incoming in listener.incoming() {
                match incoming {
                    Ok(conn) => {
                        let mut buf: [u8; 8] = [0; 8];
                        conn.recv(&mut buf).unwrap();
                        conn.send(&buf).unwrap();
                    }
                    Err(err) => {
                        eprint!("error: {}", err);
                        assert!(false);
                    }
                }
                count += 1;
                if count == 2 {
                    break;
                }
            }
        });
        
        let data1: &[u8; 8] = b"dataone1";
        let data2: &[u8; 8] = b"datatwo2";

        // First connection
        let client1 =
            SyncStream::connect(&SocketAddr::new(VMADDR_CID_LOCAL, loc.port())).unwrap();
        client1.send(data1).unwrap();
        let mut buf1: [u8; 8] = [0; 8];
        let sz1 = client1.recv(&mut buf1).unwrap();
        assert_eq!(&buf1[0..sz1], data1);

        // Second connection
        let client2 =
            SyncStream::connect(&SocketAddr::new(VMADDR_CID_LOCAL, loc.port())).unwrap();
        client2.send(data2).unwrap();
        let mut buf2: [u8; 8] = [0; 8];
        let sz2 = client2.recv(&mut buf2).unwrap();
        assert_eq!(&buf2[0..sz2], data2);

        assert!(jh.join().is_ok());
    }

    #[tokio::test]
    async fn async_echo() {
        let listener = Listener::bind(&SocketAddr::new(VMADDR_CID_ANY, VMADDR_PORT_ANY)).unwrap();
        let loc = listener.local_addr().unwrap();
        futures::join!(
            async {
                let (conn, _) = listener.accept().await.unwrap();
                let mut buf: [u8; 8] = [0; 8];
                conn.recv(&mut buf).await.unwrap();
                conn.send(&buf).await.unwrap();
            },
            async {
                let data: &[u8; 8] = b"datadata";
                let client = Stream::connect(&SocketAddr::new(VMADDR_CID_LOCAL, loc.port()))
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
        let listener = Listener::bind(&SocketAddr::new(VMADDR_CID_ANY, VMADDR_PORT_ANY)).unwrap();
        let loc = listener.local_addr().unwrap();
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
                let mut client = Stream::connect(&SocketAddr::new(VMADDR_CID_LOCAL, loc.port()))
                    .await
                    .unwrap();
                client.write(data).await.unwrap();
                let mut buf: [u8; 8] = [0; 8];
                let sz = client.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf[0..sz], data);
            }
        );
    }
}
