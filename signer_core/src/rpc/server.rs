use crate::rpc::{net::DatagramSocket, Error as RPCError, Request, Result as RPCResult};
use crate::{Sealant, SealedSigner, TryFromCBOR, TryIntoCBOR};
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
pub struct Server<S, R> {
    signer: Option<SealedSigner<S>>,
    rng: R,
}

impl<S, R> Server<S, R>
where
    S: Sealant,
    S::Credentials: DeserializeOwned,
    R: CryptoRngCore,
{
    pub fn new(r: R) -> Self {
        Server {
            signer: None,
            rng: r,
        }
    }

    pub fn serve<D: DatagramSocket>(mut self, sock: D) -> Result<(), D::Error> {
        loop {
            let mut buf: [u8; 64 * 1024] = [0; 64 * 1024];
            let (len, addr) = sock.recv_from(&mut buf)?;
            let ret = self.handle_datagram(&buf[0..len]);
            sock.send_to(&ret, &addr)?;
        }
    }

    fn handle_datagram(&mut self, src: &[u8]) -> Vec<u8> {
        match Request::<S::Credentials>::try_from_cbor(src) {
            Ok(req) => match req {
                Request::Initialize(cred) => match SealedSigner::try_new(cred) {
                    Ok(signer) => {
                        self.signer = Some(signer);
                        Ok(())
                    }
                    Err(err) => Err(RPCError::from(err)),
                }
                .try_into_cbor(),
                req => match &mut self.signer {
                    Some(signer) => match req {
                        Request::Import(key_data) => signer
                            .import(&key_data)
                            .map_err(RPCError::from)
                            .try_into_cbor(),
                        Request::Generate(t) => signer
                            .generate(t, &mut self.rng)
                            .map_err(RPCError::from)
                            .try_into_cbor(),
                        Request::GenerateAndImport(t) => signer
                            .generate_and_import(t, &mut self.rng)
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
                    },
                    None => RPCResult::<()>::Err(Error::Uninitialized.into()).try_into_cbor(),
                },
            }
            // convert the response serialization error into Error struct and serialize it
            .or_else(|err| RPCResult::<()>::Err(err.into()).try_into_cbor())
            // panic only if serialization of Error struct has failed
            .unwrap(),
            Err(err) => RPCResult::<()>::Err(err.into()).try_into_cbor().unwrap(),
        }
    }
}
