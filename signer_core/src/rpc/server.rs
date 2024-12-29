use crate::rpc::net::{AsyncDatagramSocket, DatagramSocket};
use crate::rpc::{Error as RPCError, Request, Result as RPCResult};
use crate::{AsyncSealant, AsyncSealedSigner, SealedSigner, SyncSealant, TryFromCBOR, TryIntoCBOR};
use rand_core::CryptoRngCore;
use serde::de::DeserializeOwned;

#[derive(Debug)]
pub enum Error {
    Uninitialized,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Uninitialized => f.write_str("uninitialized"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug)]
struct Inner<S, R> {
    signer: Option<S>,
    rng: R,
}

#[derive(Debug)]
pub struct Server<S, R>(Inner<SealedSigner<S>, R>);

impl<S, R> Server<S, R>
where
    S: SyncSealant,
    S::Credentials: DeserializeOwned,
    R: CryptoRngCore,
{
    pub fn new(r: R) -> Self {
        Server(Inner {
            signer: None,
            rng: r,
        })
    }

    pub fn serve<D: DatagramSocket>(mut self, sock: D) -> Result<(), D::Error> {
        loop {
            let mut buf: [u8; 64 * 1024] = [0; 64 * 1024];
            let (len, addr) = sock.recv_from(&mut buf)?;
            match self.handle_datagram(&buf[0..len]) {
                Some(ret) => {
                    sock.send_to(&ret, &addr)?;
                }
                None => break Ok(()),
            }
        }
    }

    pub fn serve_connection<D: DatagramSocket>(mut self, sock: D) -> Result<(), D::Error> {
        loop {
            let mut buf: [u8; 64 * 1024] = [0; 64 * 1024];
            let len = sock.recv(&mut buf)?;
            match self.handle_datagram(&buf[0..len]) {
                Some(ret) => {
                    sock.send(&ret)?;
                }
                None => break Ok(()),
            }
        }
    }

    fn handle_datagram(&mut self, src: &[u8]) -> Option<Vec<u8>> {
        match Request::<S::Credentials>::try_from_cbor(src) {
            Ok(req) => match req {
                Request::Terminate => None,
                Request::Initialize(cred) => Some(
                    match SealedSigner::try_new(cred) {
                        Ok(signer) => {
                            self.0.signer = Some(signer);
                            Ok(())
                        }
                        Err(err) => Err(RPCError::from(err)),
                    }
                    .try_into_cbor(),
                ),
                req => Some(match &mut self.0.signer {
                    Some(signer) => match req {
                        Request::Import(key_data) => signer
                            .import(&key_data)
                            .map_err(RPCError::from)
                            .try_into_cbor(),

                        Request::Generate(t) => signer
                            .generate(t, &mut self.0.rng)
                            .map_err(RPCError::from)
                            .try_into_cbor(),

                        Request::GenerateAndImport(t) => signer
                            .generate_and_import(t, &mut self.0.rng)
                            .map_err(RPCError::from)
                            .try_into_cbor(),

                        Request::Sign { handle, msg } => signer
                            .try_sign(handle, &msg)
                            .map_err(RPCError::from)
                            .try_into_cbor(),

                        Request::SignWith { key_data, msg } => signer
                            .try_sign_with(&key_data, &msg)
                            .map_err(RPCError::from)
                            .try_into_cbor(),

                        Request::PublicKey(handle) => signer
                            .public_key(handle)
                            .map_err(RPCError::from)
                            .try_into_cbor(),

                        Request::PublicKeyFrom(key_data) => signer
                            .public_key_from(&key_data)
                            .map_err(RPCError::from)
                            .try_into_cbor(),

                        Request::Initialize(_) => unreachable!(),
                        Request::Terminate => unreachable!(),
                    },
                    None => RPCResult::<()>::Err(Error::Uninitialized.into()).try_into_cbor(),
                }),
            }
            .map(|v|
            // convert the response serialization error into Error struct and serialize it
            v.or_else(|err| RPCResult::<()>::Err(err.into()).try_into_cbor())
            // panic only if serialization of Error struct has failed
            .unwrap()),
            Err(err) => Some(RPCResult::<()>::Err(err.into()).try_into_cbor().unwrap()),
        }
    }
}

#[derive(Debug)]
pub struct AsyncServer<S, R>(Inner<AsyncSealedSigner<S>, R>);

impl<S, R> AsyncServer<S, R>
where
    S: AsyncSealant,
    S::Credentials: DeserializeOwned,
    R: CryptoRngCore,
{
    pub fn new(r: R) -> Self {
        AsyncServer(Inner {
            signer: None,
            rng: r,
        })
    }

    pub async fn serve<D: AsyncDatagramSocket>(mut self, sock: D) -> Result<(), D::Error> {
        loop {
            let mut buf: [u8; 64 * 1024] = [0; 64 * 1024];
            let (len, addr) = sock.recv_from(&mut buf).await?;
            match self.handle_datagram(&buf[0..len]).await {
                Some(ret) => {
                    sock.send_to(&ret, &addr).await?;
                }
                None => break Ok(()),
            }
        }
    }

    pub async fn serve_connection<D: AsyncDatagramSocket>(
        mut self,
        sock: D,
    ) -> Result<(), D::Error> {
        loop {
            let mut buf: [u8; 64 * 1024] = [0; 64 * 1024];
            let len = sock.recv(&mut buf).await?;
            match self.handle_datagram(&buf[0..len]).await {
                Some(ret) => {
                    sock.send(&ret).await?;
                }
                None => break Ok(()),
            }
        }
    }

    async fn handle_datagram(&mut self, src: &[u8]) -> Option<Vec<u8>> {
        match Request::<S::Credentials>::try_from_cbor(src) {
            Ok(req) => match req {
                Request::Terminate => None,
                Request::Initialize(cred) => Some(
                    match AsyncSealedSigner::try_new(cred).await {
                        Ok(signer) => {
                            self.0.signer = Some(signer);
                            Ok(())
                        }
                        Err(err) => Err(RPCError::from(err)),
                    }
                    .try_into_cbor(),
                ),
                req => Some(match &mut self.0.signer {
                    Some(signer) => match req {
                        Request::Import(key_data) => signer
                            .import(&key_data)
                            .await
                            .map_err(RPCError::from)
                            .try_into_cbor(),

                        Request::Generate(t) => signer
                            .generate(t, &mut self.0.rng)
                            .await
                            .map_err(RPCError::from)
                            .try_into_cbor(),

                        Request::GenerateAndImport(t) => signer
                            .generate_and_import(t, &mut self.0.rng)
                            .await
                            .map_err(RPCError::from)
                            .try_into_cbor(),

                        Request::Sign { handle, msg } => signer
                            .try_sign(handle, &msg)
                            .map_err(RPCError::from)
                            .try_into_cbor(),

                        Request::SignWith { key_data, msg } => signer
                            .try_sign_with(&key_data, &msg)
                            .await
                            .map_err(RPCError::from)
                            .try_into_cbor(),

                        Request::PublicKey(handle) => signer
                            .public_key(handle)
                            .map_err(RPCError::from)
                            .try_into_cbor(),

                        Request::PublicKeyFrom(key_data) => signer
                            .public_key_from(&key_data)
                            .await
                            .map_err(RPCError::from)
                            .try_into_cbor(),

                        Request::Initialize(_) => unreachable!(),
                        Request::Terminate => unreachable!(),
                    },
                    None => RPCResult::<()>::Err(Error::Uninitialized.into()).try_into_cbor(),
                }),
            }
            .map(|v|
            // convert the response serialization error into Error struct and serialize it
            v.or_else(|err| RPCResult::<()>::Err(err.into()).try_into_cbor())
            // panic only if serialization of Error struct has failed
            .unwrap()),
            Err(err) => Some(RPCResult::<()>::Err(err.into()).try_into_cbor().unwrap()),
        }
    }
}
