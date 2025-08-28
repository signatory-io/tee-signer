use crate::rpc::{Error as RPCError, Request, Result as RPCResult};
use crate::{
    EncryptedSigner, EncryptionBackend, EncryptionBackendFactory, Error as SignerError,
    TryFromCBOR, TryIntoCBOR,
};
use rand_core::CryptoRngCore;
use serde::de::DeserializeOwned;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
pub struct Server<F, S, R> {
    fact: F,
    signer: Option<S>,
    rng: R,
}

impl<F, S, R> Server<F, S, R> {
    pub fn new(fact: F, rng: R) -> Self {
        Self {
            fact,
            signer: None,
            rng,
        }
    }
}

impl<F, R> Server<F, EncryptedSigner<F::Output>, R>
where
    F: EncryptionBackendFactory,
    F::Output: EncryptionBackend,
    F::Credentials: DeserializeOwned,
    R: CryptoRngCore,
    RPCError: From<<F::Output as EncryptionBackend>::Error>
        + From<SignerError<<F::Output as EncryptionBackend>::Error>>,
{
    pub async fn serve_connection<T: AsyncWrite + AsyncReadExt + Unpin>(
        &mut self,
        mut sock: T,
    ) -> Result<(), Error> {
        let mut buf = Vec::<u8>::new();
        let mut w_buf = Vec::<u8>::new();
        loop {
            let mut len_buf: [u8; 4] = [0; 4];
            if let Err(err) = sock.read_exact(&mut len_buf).await {
                break if err.kind() == io::ErrorKind::UnexpectedEof {
                    Ok(())
                } else {
                    Err(err.into())
                };
            }
            let len = u32::from_be_bytes(len_buf);
            buf.resize(len as usize, 0);
            sock.read_exact(&mut buf).await?;

            self.handle_message(&mut buf).await?;
            let len = u32::try_from(buf.len()).unwrap().to_be_bytes();
            w_buf.clear();
            w_buf.extend_from_slice(&len);
            w_buf.extend_from_slice(&buf);

            sock.write_all(&w_buf).await?;
        }
    }

    async fn handle_message(&mut self, buf: &mut Vec<u8>) -> Result<(), Error> {
        let req = Request::<F::Credentials>::try_from_cbor(buf);
        buf.clear();

        let req = match req {
            Ok(req) => req,
            Err(err) => {
                // return deserialization error to the client
                println!("invalid request: {}", err);
                return RPCResult::<()>::Err(err.into())
                    .try_into_writer(buf)
                    .map_err(Into::into)
                    .and(Ok(()));
            }
        };

        match (req, &mut self.signer) {
            (Request::Initialize(cred), None) => match self.fact.try_new(cred).await {
                Ok(enc) => {
                    self.signer = Some(enc.into());
                    RPCResult::<()>::Ok(())
                }
                Err(err) => RPCResult::<()>::Err(err.into()),
            }
            .try_into_writer(buf)
            .and(Ok(())),

            (Request::Initialize(_), Some(_)) => {
                RPCResult::<()>::Err(StateError::Initialized.into())
                    .try_into_writer(buf)
                    .and(Ok(()))
            }

            (_, None) => RPCResult::<()>::Err(StateError::Uninitialized.into())
                .try_into_writer(buf)
                .and(Ok(())),

            (Request::Import(key_data), Some(signer)) => signer
                .import(&key_data)
                .await
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(())),

            (Request::ImportUnencrypted(key), Some(signer)) => signer
                .import_unencrypted(key)
                .await
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(())),

            (Request::Generate(t), Some(signer)) => signer
                .generate(t, &mut self.rng)
                .await
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(())),

            (Request::GenerateAndImport(t), Some(signer)) => signer
                .generate_and_import(t, &mut self.rng)
                .await
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(())),

            (
                Request::Sign {
                    handle,
                    message: msg,
                    version,
                },
                Some(signer),
            ) => signer
                .try_sign(handle, &msg, version)
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(())),

            (
                Request::SignWith {
                    encrypted_private_key: key_data,
                    message: msg,
                    version,
                },
                Some(signer),
            ) => signer
                .try_sign_with(&key_data, &msg, version)
                .await
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(())),

            (Request::PublicKey(handle), Some(signer)) => signer
                .public_key(handle)
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(())),

            (Request::PublicKeyFrom(key_data), Some(signer)) => signer
                .public_key_from(&key_data)
                .await
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(())),

            (Request::ProvePossession(handle), Some(signer)) => signer
                .try_prove(handle)
                .map_err(RPCError::from)
                .try_into_writer(buf)
                .and(Ok(())),
        }
        .map_err(Into::into)
    }
}
