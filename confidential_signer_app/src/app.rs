use confidential_signer::base64::{Engine as _, engine::general_purpose};
use confidential_signer::error::Error;
use confidential_signer::log::{error, info, warn};
use confidential_signer::signer_core::secure::Error as SecureError;
use confidential_signer::{
    Server,
    kms_client::ClientFactory,
    rand_core,
    signer_core::secure::{AuthorizedKeys, EncryptedStream, ServerKeypair},
    tokio,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

pub struct App {
    conf: Config,
    server_keypair: Arc<ServerKeypair>,
    authorized_keys: Arc<AuthorizedKeys>,
}

pub const DEFAULT_TCP_PORT: u32 = 2000;

#[derive(Debug)]
pub struct Config {
    pub listen_port: Option<u32>,
    pub server_keypair: Option<String>,
    pub authorized_keys: Option<String>,
}

impl App {
    pub fn init(conf: Config) -> Result<Self, Error> {
        let server_keypair = if let Some(keypair_str) = &conf.server_keypair {
            let keypair_bytes = general_purpose::STANDARD
                .decode(keypair_str)
                .map_err(|e| Error::Secure(SecureError::Base64Decode(e)))?;
            if keypair_bytes.len() != 64 {
                return Err(Error::Secure(SecureError::InvalidKeyLength));
            }
            ServerKeypair::from_bytes(&keypair_bytes)?
        } else {
            warn!("WARNING: No SERVER_KEYPAIR provided, generating ephemeral keypair");
            let keypair = ServerKeypair::generate();
            let pubkey_b64 = general_purpose::STANDARD.encode(keypair.public_key());
            info!("Server public key (base64): {}", pubkey_b64);
            keypair
        };

        let authorized_keys = if let Some(keys_str) = &conf.authorized_keys {
            AuthorizedKeys::parse(keys_str)?
        } else {
            warn!("WARNING: No AUTHORIZED_KEYS provided, accepting all clients (INSECURE)");
            AuthorizedKeys::new_accept_all()
        };

        if authorized_keys.is_empty() {
            warn!("WARNING: Running in accept-all mode (INSECURE)");
        }

        Ok(Self {
            conf,
            server_keypair: Arc::new(server_keypair),
            authorized_keys: Arc::new(authorized_keys),
        })
    }

    pub async fn run(self) -> Result<(), Error> {
        let addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            self.conf.listen_port.unwrap_or(DEFAULT_TCP_PORT) as u16,
        );

        let listener = tokio::net::TcpListener::bind(addr).await?;
        info!("Listening on {} with secure connections", addr);

        let server_keypair = self.server_keypair.clone();
        let authorized_keys = self.authorized_keys.clone();

        loop {
            let (mut conn, addr) = listener.accept().await?;

            let keypair = server_keypair.clone();
            let auth_keys = authorized_keys.clone();

            tokio::spawn(async move {
                let conn_state = match confidential_signer::signer_core::secure::perform_handshake(
                    &mut conn, &keypair, &auth_keys,
                )
                .await
                {
                    Ok(state) => state,
                    Err(e) => {
                        error!("Connection from {} - Handshake failed: {}", addr, e);
                        return;
                    }
                };

                let encrypted_conn = EncryptedStream::new(conn, conn_state.session);

                let cf = ClientFactory::new();
                let mut srv = Server::new(cf, rand_core::OsRng);

                if let Err(err) = srv.serve_connection_secure(encrypted_conn).await {
                    error!("Connection from {} closed with error: {}", addr, err);
                }
            });
        }
    }
}
