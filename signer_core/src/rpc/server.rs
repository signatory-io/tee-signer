use crate::rpc::{Error as RPCError, Request, Result as RPCResult};
use crate::{AsyncSealant, AsyncSealedSigner, SealedSigner, SyncSealant, TryFromCBOR, TryIntoCBOR};
use rand_core::CryptoRngCore;
use serde::de::DeserializeOwned;
use std::io::{self, Read, Write};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug)]
pub enum StateError {
    Uninitialized,
    Initialized,
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateError::Uninitialized => f.write_str("uninitialized"),
            StateError::Initialized => f.write_str("already initialized"),
        }
    }
}

impl std::error::Error for StateError {}

#[derive(Debug)]
pub enum Error {
    IO(std::io::Error),
    Serialize(ciborium::ser::Error<io::Error>),
    Deserialize(ciborium::de::Error<io::Error>),
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::IO(value)
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
            Error::Serialize(error) => write!(f, "serialization error: {}", error),
            Error::Deserialize(error) => write!(f, "deserialization error: {}", error),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug)]
struct Inner<S, R> {
    signer: Option<S>,
    rng: R,
}

impl<S, R> Inner<S, R> {
    pub fn new(r: R) -> Self {
        Self {
            signer: None,
            rng: r,
        }
    }
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
        Self(Inner::new(r))
    }

    pub fn serve_connection<T: Read + Write>(&mut self, mut sock: T) -> Result<(), Error> {
        let mut buf = Vec::<u8>::new();
        let mut w_buf = Vec::<u8>::new();
        loop {
            let mut len_buf: [u8; 4] = [0; 4];
            sock.read_exact(&mut len_buf)?;
            let len = u32::from_be_bytes(len_buf);

            buf.resize(len as usize, 0);
            sock.read_exact(&mut buf)?;

            let ok = self.handle_message(&mut buf)?;
            let len = (buf.len() as u32).to_be_bytes();
            w_buf.clear();
            w_buf.extend_from_slice(&len);
            w_buf.extend_from_slice(&buf);
            sock.write_all(&w_buf)?;
            if !ok {
                break Ok(());
            }
        }
    }

    fn handle_message(&mut self, buf: &mut Vec<u8>) -> Result<bool, Error> {
        let req = Request::<S::Credentials>::try_from_cbor(buf);
        buf.clear();

        let req = match req {
            Ok(req) => req,
            Err(err) => {
                // return deserialization error to the client
                return RPCResult::<()>::Err(err.into())
                    .try_into_writer(buf)
                    .map_err(Into::into)
                    .and(Ok(true));
            }
        };

        match (req, &mut self.0.signer) {
            (Request::Terminate, _) => RPCResult::<()>::Ok(()).try_into_writer(buf).and(Ok(false)),

            (Request::Initialize(cred), None) => match SealedSigner::try_new(cred) {
                Ok(signer) => {
                    self.0.signer = Some(signer);
                    RPCResult::<()>::Ok(())
                }
                Err(err) => RPCResult::<()>::Err(err.into()),
            }
            .try_into_writer(buf)
            .and(Ok(true)),

            (Request::Initialize(_), Some(_)) => {
                RPCResult::<()>::Err(StateError::Initialized.into())
                    .try_into_writer(buf)
                    .and(Ok(true))
            }

            (_, None) => RPCResult::<()>::Err(StateError::Uninitialized.into())
                .try_into_writer(buf)
                .and(Ok(true)),

            (Request::Import(key_data), Some(signer)) => signer
                .import(&key_data)
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(true)),

            (Request::Generate(t), Some(signer)) => signer
                .generate(t, &mut self.0.rng)
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(true)),

            (Request::GenerateAndImport(t), Some(signer)) => signer
                .generate_and_import(t, &mut self.0.rng)
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(true)),

            (Request::Sign { handle, msg }, Some(signer)) => signer
                .try_sign(handle, &msg)
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(true)),

            (Request::SignWith { key_data, msg }, Some(signer)) => signer
                .try_sign_with(&key_data, &msg)
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(true)),

            (Request::PublicKey(handle), Some(signer)) => signer
                .public_key(handle)
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(true)),

            (Request::PublicKeyFrom(key_data), Some(signer)) => signer
                .public_key_from(&key_data)
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(true)),
        }
        .map_err(Into::into)
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
        Self(Inner::new(r))
    }

    pub async fn serve_connection<T: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        mut sock: T,
    ) -> Result<(), Error> {
        let mut buf = Vec::<u8>::new();
        let mut w_buf = Vec::<u8>::new();
        loop {
            let mut len_buf: [u8; 4] = [0; 4];
            sock.read_exact(&mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf);

            buf.resize(len as usize, 0);
            sock.read_exact(&mut buf).await?;

            let ok = self.handle_message(&mut buf).await?;
            let len = (buf.len() as u32).to_be_bytes();
            w_buf.clear();
            w_buf.extend_from_slice(&len);
            w_buf.extend_from_slice(&buf);
            sock.write_all(&w_buf).await?;
            if !ok {
                break Ok(());
            }
        }
    }

    async fn handle_message(&mut self, buf: &mut Vec<u8>) -> Result<bool, Error> {
        let req = Request::<S::Credentials>::try_from_cbor(buf);
        buf.clear();

        let req = match req {
            Ok(req) => req,
            Err(err) => {
                // return deserialization error to the client
                return RPCResult::<()>::Err(err.into())
                    .try_into_writer(buf)
                    .map_err(Into::into)
                    .and(Ok(true));
            }
        };

        match (req, &mut self.0.signer) {
            (Request::Terminate, _) => RPCResult::<()>::Ok(()).try_into_writer(buf).and(Ok(false)),

            (Request::Initialize(cred), None) => match AsyncSealedSigner::try_new(cred).await {
                Ok(signer) => {
                    self.0.signer = Some(signer);
                    RPCResult::<()>::Ok(())
                }
                Err(err) => RPCResult::<()>::Err(err.into()),
            }
            .try_into_writer(buf)
            .and(Ok(true)),

            (Request::Initialize(_), Some(_)) => {
                RPCResult::<()>::Err(StateError::Initialized.into())
                    .try_into_writer(buf)
                    .and(Ok(true))
            }

            (_, None) => RPCResult::<()>::Err(StateError::Uninitialized.into())
                .try_into_writer(buf)
                .and(Ok(true)),

            (Request::Import(key_data), Some(signer)) => signer
                .import(&key_data)
                .await
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(true)),

            (Request::Generate(t), Some(signer)) => signer
                .generate(t, &mut self.0.rng)
                .await
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(true)),

            (Request::GenerateAndImport(t), Some(signer)) => signer
                .generate_and_import(t, &mut self.0.rng)
                .await
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(true)),

            (Request::Sign { handle, msg }, Some(signer)) => signer
                .try_sign(handle, &msg)
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(true)),

            (Request::SignWith { key_data, msg }, Some(signer)) => signer
                .try_sign_with(&key_data, &msg)
                .await
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(true)),

            (Request::PublicKey(handle), Some(signer)) => signer
                .public_key(handle)
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(true)),

            (Request::PublicKeyFrom(key_data), Some(signer)) => signer
                .public_key_from(&key_data)
                .await
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(true)),
        }
        .map_err(Into::into)
    }
}
