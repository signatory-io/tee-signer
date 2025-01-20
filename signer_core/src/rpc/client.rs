use crate::crypto::{KeyType, PublicKey, Signature};
use crate::rpc::{Error as RPCError, Request, Result as RPCResult};
use crate::{TryFromCBOR, TryIntoCBOR};
use serde::Serialize;
use std::io::{Read, Write};
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug)]
pub enum Error {
    IO(std::io::Error),
    RPC(RPCError),
    Serialize(ciborium::ser::Error<std::io::Error>),
    Deserialize(ciborium::de::Error<std::io::Error>),
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::IO(value)
    }
}

impl From<RPCError> for Error {
    fn from(value: RPCError) -> Self {
        Error::RPC(value)
    }
}

impl From<ciborium::de::Error<std::io::Error>> for Error {
    fn from(value: ciborium::de::Error<std::io::Error>) -> Self {
        Error::Deserialize(value)
    }
}

impl From<ciborium::ser::Error<std::io::Error>> for Error {
    fn from(value: ciborium::ser::Error<std::io::Error>) -> Self {
        Error::Serialize(value)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IO(error) => write!(f, "IO error: {}", error),
            Error::RPC(error) => write!(f, "RPC error: {}", error),
            Error::Serialize(error) => write!(f, "serialization error: {}", error),
            Error::Deserialize(error) => write!(f, "deserialization error: {}", error),
        }
    }
}

impl std::error::Error for Error {}

struct Inner<T, C> {
    socket: T,
    buf: Vec<u8>,
    w_buf: Vec<u8>,
    _phantom: PhantomData<C>,
}

impl<T, C> Inner<T, C> {
    pub fn new(sock: T) -> Self {
        Self {
            socket: sock,
            buf: Vec::new(),
            w_buf: Vec::new(),
            _phantom: PhantomData,
        }
    }
}

pub struct Client<T, C>(Inner<T, C>);

impl<T, C> Client<T, C>
where
    T: Read + Write,
    C: Serialize,
{
    pub fn new(sock: T) -> Self {
        Self(Inner::new(sock))
    }

    fn round_trip<R>(&mut self, req: Request<C>) -> Result<R, Error>
    where
        R: TryFromCBOR,
        Request<C>: TryIntoCBOR,
        RPCResult<R>: TryFromCBOR,
        Error:
            From<<Request<C> as TryIntoCBOR>::Error> + From<<RPCResult<R> as TryFromCBOR>::Error>,
    {
        self.0.buf.clear();
        req.try_into_writer(&mut self.0.buf)?;
        let len = u32::try_from(self.0.buf.len()).unwrap().to_be_bytes();

        self.0.w_buf.clear();
        self.0.w_buf.extend_from_slice(&len);
        self.0.w_buf.extend_from_slice(&self.0.buf);
        self.0.socket.write_all(&self.0.w_buf)?;

        let mut len_buf: [u8; 4] = [0; 4];
        self.0.socket.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf);

        self.0.buf.resize(len as usize, 0);
        self.0.socket.read_exact(&mut self.0.buf)?;

        let res = RPCResult::<R>::try_from_cbor(&self.0.buf)?;
        Ok(res?)
    }

    pub fn initialize(&mut self, cred: C) -> Result<(), Error> {
        self.round_trip::<()>(Request::Initialize(cred))
    }

    pub fn terminate(&mut self) -> Result<(), Error> {
        self.round_trip::<()>(Request::Terminate(()))
    }

    pub fn import(&mut self, key_data: &[u8]) -> Result<(PublicKey, usize), Error> {
        self.round_trip::<(PublicKey, usize)>(Request::Import(key_data.into()))
    }

    pub fn generate(&mut self, t: KeyType) -> Result<(Vec<u8>, PublicKey), Error> {
        self.round_trip::<(Vec<u8>, PublicKey)>(Request::Generate(t))
    }

    pub fn generate_and_import(
        &mut self,
        t: KeyType,
    ) -> Result<(Vec<u8>, PublicKey, usize), Error> {
        self.round_trip::<(Vec<u8>, PublicKey, usize)>(Request::GenerateAndImport(t))
    }

    pub fn try_sign(&mut self, handle: usize, msg: &[u8]) -> Result<Signature, Error> {
        self.round_trip::<Signature>(Request::Sign {
            handle: handle,
            msg: msg.into(),
        })
    }

    pub fn try_sign_with(&mut self, key_data: &[u8], msg: &[u8]) -> Result<Signature, Error> {
        self.round_trip::<Signature>(Request::SignWith {
            key_data: key_data.into(),
            msg: msg.into(),
        })
    }

    pub fn public_key(&mut self, handle: usize) -> Result<PublicKey, Error> {
        self.round_trip::<PublicKey>(Request::PublicKey(handle))
    }

    pub fn public_key_from(&mut self, key_data: &[u8]) -> Result<PublicKey, Error> {
        self.round_trip::<PublicKey>(Request::PublicKeyFrom(key_data.into()))
    }
}

pub struct AsyncClient<T, C>(Inner<T, C>);

impl<T, C> AsyncClient<T, C>
where
    T: AsyncRead + AsyncWrite + Unpin,
    C: Serialize,
{
    pub fn new(sock: T) -> Self {
        Self(Inner::new(sock))
    }

    async fn round_trip<R>(&mut self, req: Request<C>) -> Result<R, Error>
    where
        R: TryFromCBOR,
        Request<C>: TryIntoCBOR,
        RPCResult<R>: TryFromCBOR,
        Error:
            From<<Request<C> as TryIntoCBOR>::Error> + From<<RPCResult<R> as TryFromCBOR>::Error>,
    {
        self.0.buf.clear();
        req.try_into_writer(&mut self.0.buf)?;
        let len = u32::try_from(self.0.buf.len()).unwrap().to_be_bytes();

        self.0.w_buf.clear();
        self.0.w_buf.extend_from_slice(&len);
        self.0.w_buf.extend_from_slice(&self.0.buf);
        self.0.socket.write_all(&self.0.w_buf).await?;

        let mut len_buf: [u8; 4] = [0; 4];
        self.0.socket.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf);

        self.0.buf.resize(len as usize, 0);
        self.0.socket.read_exact(&mut self.0.buf).await?;

        let res = RPCResult::<R>::try_from_cbor(&self.0.buf)?;
        Ok(res?)
    }

    pub async fn initialize(&mut self, cred: C) -> Result<(), Error> {
        self.round_trip::<()>(Request::Initialize(cred)).await
    }

    pub async fn terminate(&mut self) -> Result<(), Error> {
        self.round_trip::<()>(Request::Terminate(())).await
    }

    pub async fn import(&mut self, key_data: &[u8]) -> Result<(PublicKey, usize), Error> {
        self.round_trip::<(PublicKey, usize)>(Request::Import(key_data.into()))
            .await
    }

    pub async fn generate(&mut self, t: KeyType) -> Result<(Vec<u8>, PublicKey), Error> {
        self.round_trip::<(Vec<u8>, PublicKey)>(Request::Generate(t))
            .await
    }

    pub async fn generate_and_import(
        &mut self,
        t: KeyType,
    ) -> Result<(Vec<u8>, PublicKey, usize), Error> {
        self.round_trip::<(Vec<u8>, PublicKey, usize)>(Request::GenerateAndImport(t))
            .await
    }

    pub async fn try_sign(&mut self, handle: usize, msg: &[u8]) -> Result<Signature, Error> {
        self.round_trip::<Signature>(Request::Sign {
            handle: handle,
            msg: msg.into(),
        })
        .await
    }

    pub async fn try_sign_with(&mut self, key_data: &[u8], msg: &[u8]) -> Result<Signature, Error> {
        self.round_trip::<Signature>(Request::SignWith {
            key_data: key_data.into(),
            msg: msg.into(),
        })
        .await
    }

    pub async fn public_key(&mut self, handle: usize) -> Result<PublicKey, Error> {
        self.round_trip::<PublicKey>(Request::PublicKey(handle))
            .await
    }

    pub async fn public_key_from(&mut self, key_data: &[u8]) -> Result<PublicKey, Error> {
        self.round_trip::<PublicKey>(Request::PublicKeyFrom(key_data.into()))
            .await
    }
}
