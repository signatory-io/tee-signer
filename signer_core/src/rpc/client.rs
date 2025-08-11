use crate::crypto::{KeyType, PrivateKey, PublicKey, Signature, SigningVersion};
use crate::rpc::{
    Error as RPCError, GenerateAndImportResult, GenerateResult, ImportResult, Request,
    Result as RPCResult,
};
use crate::{TryFromCBOR, TryIntoCBOR};
use serde::Serialize;
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

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

pub struct Client<T, C> {
    socket: T,
    buf: Vec<u8>,
    w_buf: Vec<u8>,
    _phantom: PhantomData<C>,
}

impl<T, C> Client<T, C>
where
    T: AsyncRead + AsyncWriteExt + Unpin,
    C: Serialize,
{
    pub fn new(sock: T) -> Self {
        Self {
            socket: sock,
            buf: Vec::new(),
            w_buf: Vec::new(),
            _phantom: PhantomData,
        }
    }

    async fn round_trip<R>(&mut self, req: Request<C>) -> Result<R, Error>
    where
        R: TryFromCBOR,
        Request<C>: TryIntoCBOR,
        RPCResult<R>: TryFromCBOR,
        Error:
            From<<Request<C> as TryIntoCBOR>::Error> + From<<RPCResult<R> as TryFromCBOR>::Error>,
    {
        self.buf.clear();
        req.try_into_writer(&mut self.buf)?;
        let len = u32::try_from(self.buf.len()).unwrap().to_be_bytes();

        self.w_buf.clear();
        self.w_buf.extend_from_slice(&len);
        self.w_buf.extend_from_slice(&self.buf);
        self.socket.write_all(&self.w_buf).await?;

        let mut len_buf: [u8; 4] = [0; 4];
        self.socket.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf);

        self.buf.resize(len as usize, 0);
        self.socket.read_exact(&mut self.buf).await?;

        let res = RPCResult::<R>::try_from_cbor(&self.buf)?;
        Ok(res?)
    }

    pub async fn initialize(&mut self, cred: C) -> Result<(), Error> {
        self.round_trip::<()>(Request::Initialize(cred)).await
    }

    pub async fn import(&mut self, key_data: &[u8]) -> Result<ImportResult, Error> {
        self.round_trip::<ImportResult>(Request::Import(key_data.into()))
            .await
    }

    pub async fn import_unencrypted(
        &mut self,
        private_key: &PrivateKey,
    ) -> Result<GenerateAndImportResult, Error> {
        self.round_trip::<GenerateAndImportResult>(Request::ImportUnencrypted(private_key.clone()))
            .await
    }

    pub async fn generate(&mut self, t: KeyType) -> Result<GenerateResult, Error> {
        self.round_trip::<GenerateResult>(Request::Generate(t))
            .await
    }

    pub async fn generate_and_import(
        &mut self,
        t: KeyType,
    ) -> Result<GenerateAndImportResult, Error> {
        self.round_trip::<GenerateAndImportResult>(Request::GenerateAndImport(t))
            .await
    }

    pub async fn try_sign(
        &mut self,
        handle: usize,
        msg: &[u8],
        version: SigningVersion,
    ) -> Result<Signature, Error> {
        self.round_trip::<Signature>(Request::Sign {
            handle: handle,
            message: msg.into(),
            version,
        })
        .await
    }

    pub async fn try_sign_with(
        &mut self,
        key_data: &[u8],
        msg: &[u8],
        version: SigningVersion,
    ) -> Result<Signature, Error> {
        self.round_trip::<Signature>(Request::SignWith {
            encrypted_private_key: key_data.into(),
            message: msg.into(),
            version,
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

    pub async fn proof_of_possession(&mut self, handle: usize) -> Result<Signature, Error> {
        self.round_trip::<Signature>(Request::ProvePossession(handle))
            .await
    }
}
