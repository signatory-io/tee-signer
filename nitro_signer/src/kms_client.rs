mod vsock_proxy_client;

use aws_config::SdkConfig;
pub use aws_sdk_kms::types::{EncryptionAlgorithmSpec, KeyEncryptionMechanism};
use aws_sdk_kms::{
    client::Client as KMSClient,
    config::{Credentials as AWSCredentials, Region, SharedCredentialsProvider},
    error::SdkError,
    types::RecipientInfo,
};
use cbc::cipher::{self, block_padding, BlockDecryptMut, IvSizeUser, KeyIvInit, KeySizeUser};
use const_oid::{
    db::{
        rfc5911::{ID_AES_256_CBC, ID_DATA, ID_ENVELOPED_DATA},
        rfc5912::ID_RSAES_OAEP,
    },
    ObjectIdentifier,
};
use rsa::{Oaep, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use signer_core::{AsyncSealant, Sealant, SealantFactory};
use vsock::SocketAddr as VSockAddr;
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub attestation_doc: Vec<u8>,
    pub algorithm_spec: Option<EncryptionAlgorithmSpec>,
    pub key_id: Option<String>,
    pub proxy_port: Option<u32>,
    pub proxy_cid: Option<u32>,
    pub region: String,
    pub endpoint: Option<String>,
    pub client_key: RsaPrivateKey,
}

pub const DEFAULT_VSOCK_PROXY_PORT: u32 = 8000;
pub const DEFAULT_VSOCK_PROXY_CID: u32 = 3;

pub struct ClientFactory {
    sdk_config: aws_config::SdkConfig,
    config: Config,
}

impl ClientFactory {
    pub fn new(config: Config, sdk_config: SdkConfig) -> Self {
        Self { sdk_config, config }
    }
}

impl SealantFactory for ClientFactory {
    type Output = Client;
    type Credentials = Credentials;

    fn try_new(
        &self,
        credentials: Self::Credentials,
    ) -> Result<Self::Output, <Client as Sealant>::Error> {
        let cred = AWSCredentials::new(
            &credentials.access_key_id,
            &credentials.secret_access_key,
            None,
            None,
            "RPC",
        );

        let mut builder = self
            .sdk_config
            .to_builder()
            .credentials_provider(SharedCredentialsProvider::new(cred))
            .region(Region::new(self.config.region.clone()))
            .http_client(vsock_proxy_client::build(VSockAddr::new(
                self.config.proxy_cid.unwrap_or(DEFAULT_VSOCK_PROXY_CID),
                self.config.proxy_port.unwrap_or(DEFAULT_VSOCK_PROXY_PORT),
            )));

        if let Some(ep) = &self.config.endpoint {
            builder.set_endpoint_url(Some(ep.clone()));
        }

        let conf = builder.build();
        Ok(Client {
            config: self.config.clone(),
            client: KMSClient::new(&conf),
        })
    }
}

pub struct Client {
    client: KMSClient,
    config: Config,
}

impl Client {}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
struct ParsedEnvelopedData {
    cipher_key: Vec<u8>,
    iv: Vec<u8>,
    cipher_text: Vec<u8>,
}

const ENVELOPED_DATA_VERSION: u8 = 2;
const ENVELOPED_DATA_RECIPIENT_VERSION: u8 = 2;

fn parse_enveloped_data(src: &[u8]) -> Result<ParsedEnvelopedData, Error> {
    use ale::ExpectSome;
    let mut stream = ale::Stream::new(src);

    // ContentInfo
    let content_info = ale::new_document(&mut stream, Some(ale::ASN1_SEQUENCE)).expect_some()?;
    let ct = content_info
        .get_tagged::<ObjectIdentifier>(&mut stream)
        .expect_some()?;
    if ct != ID_ENVELOPED_DATA {
        return Err(Error::ContentType(ct));
    }
    let wrap = content_info
        .get_elem(
            &mut stream,
            Some(0 | ale::ASN1_CONSTRUCTED | ale::ASN1_CONTEXT_SPECIFIC),
        )
        .expect_some()?;
    // EnvelopedData
    let contents = wrap
        .get_elem(&mut stream, Some(ale::ASN1_SEQUENCE))
        .expect_some()?;
    let ver = contents.get_tagged::<u8>(&mut stream).expect_some()?;
    if ver != ENVELOPED_DATA_VERSION {
        return Err(Error::Version(ver));
    }

    // skip OriginatorInfo
    if let Some(oi) = contents.get_optional(
        &mut stream,
        0 | ale::ASN1_CONSTRUCTED | ale::ASN1_CONTEXT_SPECIFIC,
    )? {
        oi.consume(&mut stream)?;
    }

    // RecipientInfos
    let ri = contents
        .get_elem(&mut stream, Some(ale::ASN1_SET))
        .expect_some()?;

    // RecipientInfos
    let recipient_info = ri
        .get_elem(&mut stream, Some(ale::ASN1_SEQUENCE))
        .expect_some()?;

    let ver = recipient_info.get_tagged::<u8>(&mut stream).expect_some()?;
    if ver != ENVELOPED_DATA_RECIPIENT_VERSION {
        return Err(Error::Version(ver));
    }

    // skip RecipientIdentifier
    recipient_info
        .get_elem(&mut stream, None)
        .expect_some()?
        .consume(&mut stream)?;

    // KeyEncryptionAlgorithmIdentifier
    let ai = recipient_info
        .get_elem(&mut stream, Some(ale::ASN1_SEQUENCE))
        .expect_some()?;
    let algo = ai
        .get_tagged::<ObjectIdentifier>(&mut stream)
        .expect_some()?;
    if algo != ID_RSAES_OAEP {
        return Err(Error::Algorithm(algo));
    }
    ai.consume(&mut stream)?;

    let encrypted_key = recipient_info
        .get_elem(&mut stream, Some(ale::ASN1_OCTETSTRING))
        .expect_some()?
        .get_bytes(&mut stream)?;

    recipient_info.consume(&mut stream)?;
    ri.consume(&mut stream)?;

    // EncryptedContentInfo
    let encrypted_content_info = contents
        .get_elem(&mut stream, Some(ale::ASN1_SEQUENCE))
        .expect_some()?;
    let ct = encrypted_content_info
        .get_tagged::<ObjectIdentifier>(&mut stream)
        .expect_some()?;
    if ct != ID_DATA {
        return Err(Error::ContentType(ct));
    }

    let ai = encrypted_content_info
        .get_elem(&mut stream, Some(ale::ASN1_SEQUENCE))
        .expect_some()?;
    let algo = ai
        .get_tagged::<ObjectIdentifier>(&mut stream)
        .expect_some()?;
    if algo != ID_AES_256_CBC {
        return Err(Error::Algorithm(algo));
    }
    let iv = ai
        .get_elem(&mut stream, Some(ale::ASN1_OCTETSTRING))
        .expect_some()?
        .get_bytes(&mut stream)?;
    ai.consume(&mut stream)?;

    // EncryptedContent
    let encrypted_content = encrypted_content_info
        .get_elem(&mut stream, None)
        .expect_some()?;
    let cipher_text = if encrypted_content.tag == 0 | ale::ASN1_CONTEXT_SPECIFIC {
        Vec::from(encrypted_content.get_bytes(&mut stream)?)
    } else if encrypted_content.tag & ale::ASN1_CONSTRUCTED != 0 {
        let mut data: Vec<u8> = Vec::with_capacity(stream.len());
        while let Some(chunk) =
            encrypted_content.get_elem(&mut stream, Some(ale::ASN1_OCTETSTRING))?
        {
            data.extend_from_slice(chunk.get_bytes(&mut stream)?);
        }
        data
    } else {
        return Err(Error::Ber(ale::Error::Tag(encrypted_content.tag)));
    };

    encrypted_content_info.consume(&mut stream)?;
    contents.consume(&mut stream)?;
    wrap.consume(&mut stream)?;
    content_info.consume(&mut stream)?;

    Ok(ParsedEnvelopedData {
        cipher_key: encrypted_key.into(),
        iv: iv.into(),
        cipher_text,
    })
}

#[derive(Debug)]
pub enum Error {
    Sdk(aws_sdk_kms::Error),
    Ber(ale::Error),
    ContentType(ObjectIdentifier),
    Algorithm(ObjectIdentifier),
    Version(u8),
    MissingData,
    ZeroOutput,
    Rsa(rsa::Error),
    KeySize(usize),
    IvSize(usize),
    Unpad,
}

impl<E, R> From<SdkError<E, R>> for Error
where
    aws_sdk_kms::Error: From<SdkError<E, R>>,
{
    fn from(value: SdkError<E, R>) -> Self {
        Error::Sdk(value.into())
    }
}

impl From<ale::Error> for Error {
    fn from(value: ale::Error) -> Self {
        Error::Ber(value)
    }
}

impl From<rsa::Error> for Error {
    fn from(value: rsa::Error) -> Self {
        Error::Rsa(value)
    }
}

impl From<block_padding::UnpadError> for Error {
    fn from(_: block_padding::UnpadError) -> Self {
        Error::Unpad
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Sdk(error) => write!(f, "SDK error: {}", error),
            Error::ZeroOutput => f.write_str("zero output"),
            Error::Ber(error) => write!(f, "BER error: {}", error),
            Error::ContentType(object_identifier) => {
                write!(f, "unexpected content type: {}", object_identifier)
            }
            Error::Version(cms_version) => write!(f, "unexpected CMS version: {:?}", cms_version),
            Error::Algorithm(object_identifier) => {
                write!(f, "unexpected encryption algorithm: {}", object_identifier)
            }
            Error::MissingData => f.write_str("some data is missing"),
            Error::Rsa(error) => write!(f, "RSA error: {}", error),
            Error::KeySize(v) => write!(f, "invalid key size: {}", v),
            Error::IvSize(v) => write!(f, "invalid iv size: {}", v),
            Error::Unpad => f.write_str("unpad error"),
        }
    }
}

impl std::error::Error for Error {}

impl Sealant for Client {
    type Error = Error;
}

impl AsyncSealant for Client {
    async fn seal(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let res = self
            .client
            .encrypt()
            .plaintext(src.into())
            .set_key_id(self.config.key_id.clone())
            .set_encryption_algorithm(self.config.algorithm_spec.clone())
            .send()
            .await?;

        match res.ciphertext_blob {
            Some(val) => Ok(val.into()),
            None => Err(Error::ZeroOutput),
        }
    }

    async fn unseal(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let ri = RecipientInfo::builder()
            .attestation_document((&self.config.attestation_doc[..]).into())
            .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
            .build();

        let res = self
            .client
            .decrypt()
            .ciphertext_blob(src.into())
            .set_key_id(self.config.key_id.clone())
            .set_encryption_algorithm(self.config.algorithm_spec.clone())
            .recipient(ri)
            .send()
            .await?;

        match res.ciphertext_for_recipient {
            Some(val) => {
                let data = parse_enveloped_data(val.as_ref())?;
                decrypt_cfr(&data, &self.config.client_key)
            }
            None => Err(Error::ZeroOutput),
        }
    }
}

type Aes256Cbc = cbc::Decryptor<aes::Aes256>;

fn decrypt_cfr(data: &ParsedEnvelopedData, client_key: &RsaPrivateKey) -> Result<Vec<u8>, Error> {
    let mut cipher_key = client_key.decrypt(Oaep::new::<sha2::Sha256>(), &data.cipher_key)?;

    if cipher_key.len() != Aes256Cbc::key_size() {
        return Err(Error::KeySize(cipher_key.len()));
    }
    if data.iv.len() != Aes256Cbc::iv_size() {
        return Err(Error::IvSize(data.iv.len()));
    }

    let key_buf = cipher::Key::<Aes256Cbc>::clone_from_slice(&cipher_key);
    cipher_key.zeroize();
    let iv_buf = cipher::Iv::<Aes256Cbc>::clone_from_slice(&data.iv);

    let dec = Aes256Cbc::new(&key_buf, &iv_buf);
    Ok(dec.decrypt_padded_vec_mut::<block_padding::Pkcs7>(&data.cipher_text)?)
}

#[test]
fn parse_and_decrypt() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use rsa::pkcs1::DecodeRsaPrivateKey;

    const RSA_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwg8xlWTIwm44aLEqiA5lweHUSm2eeKwrTg3qEUhOVyGAo3eN
XRoD9wOHzjcvS8r/qfQdSdLA9p6IbSxV9LU2fXgYnT3IDhNuQ1rVkiIYqWqPWUn2
izUMJmbdVFRsgWi7/keXkslZD0DeKQM1R2QsCRZnPGHU3Jo/+2b6dTg8IRoBH2cq
rAPuynqBXYCC9+wNdYMQLA5vdaVzhFBASIVkMDDWlMaFgdOsISMHy9Klm0cXj3RE
02VsHcOQ1NRLY4Ddgpb5r0LUB0nfB4HMeK9plYqkkVF5BJihoGtGmebGuMqSFNgU
XflrxH152bHAZqqV+aIPIy2y4IdaQgP1VJrVKwIDAQABAoIBAQCQhtJNyh6+t2np
hrD/XYGpkPATcmqIwukJm9FMh8ZYnAn7NKmiwiJb0FRPX8gosYoRYE6D0aOGyPEg
Jdnqgx+O+GeUjBO3b/85yKewyxYE7ujN/gjRCnP/EbMbADlDc+Y27cjUOILMmmoa
r1n5zoABUJ8YWGA43+Rw7vPvYy9dEn1fbmsp850u/Grqdi0MUwIpQe9VKkVsYZ0n
HKAz+uY9Mhb/CsveD75cHrpaa5Ilfjkzo47Gah/+E6LB3/5wRjlzNzLMAQT449PW
yt2E/DYtVAR8uAtbfHB3cFcgNrWVg9IwU1G74SwqqwgQfpfEqKqsqG9BBXz0vwLT
o3vczVWZAoGBANJbz5+1XRlblmDV8MnVGoaHoylIA6+xE5iTiAUtopxfh3lMgTAh
sIepf7na0nkNPXFrR48Tkm29Y4f8EU2LY0a1t9WyAyufz9UTA4ABlHCuKztSqpG7
SgGEQvr/bAE61uN7JwVXGUICAR27OVfy7+iIOCzFDaOwhyfrE2XuP82VAoGBAOwq
DYedgoxuV63BWYDtvUt4olQbBCczJKyDirTGGdiPyQbsfE5eegcfZYxRkiCJ0Z5z
9OQlafIrok93kwkWgta2dj3onbXKLUviyGMSW1kGXoaTZu47rTZ7nxhqS5QeySGl
sHs/8j3+2UPHnwvLMlrMAOhIFQYrlFeQkxvIw+e/AoGAZh2Xjon2JccmGuAAQZon
hEL326RP1cv6HUkQ8KKUm6BsHWAcHodcMJ8Bl/E31vesahCP7k6r+IXFeU/N/ny5
tqukECKYE2dC9saCHnOl4YVLC0M39gKbDF1uPnYbsgUkJ82yxY7gfgCHFi26yozu
FU17J5CI7HtXQPOGuSaM5nkCgYEAqI4PIAbMYVxz2cDRF9MWsuIDwdGSckPvXe14
tzNYyRc+nGF3CxwlLiY7fR3PFMgow1XxqFAHwN9htiQa3nahpYuO8vqubUxCbhIL
gaJdbjm8h4J3CXuwUd2DnJJpJOugFBLE1gK664KUIOs92dYKN4G4+BBSaRf7hU/b
nw34vNMCgYBfG/VbQXT1WCcJgVycnU1hX7zmyzB/hk0xkmLR0nUzTgXMKOKUUXgX
2mD7U5VGZPYj7t8P+bz6/HEZqKmOoxFkXpsMPug34ZUWfjv3uCm7CFHtxA+BDT+5
cJEGAbCDYhyjvtjBLNy7YDQ1hdmCnqMxg/5AIwUMkvTTRg+qepfboA==
-----END RSA PRIVATE KEY-----
";

    const CIPHER_TEXT_STR: &str = "MIAGCSqGSIb3DQEHA6CAMIACAQIxggFrMIIBZwIBAoAgljGgxlmRCtWqvB/s/Aw+ZNTDlc6Uka86SLVmlNmFGAMwPAYJKoZIhvcNAQEHMC+gDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEFAASCAQAXmjTiHpg+OcYaf2ISaDNpQcEOq61Sm3re3v+5z2hZPe8eoUGhmMS6pCuC+BRW7RpkjwDaXQzzR/jExnraEET3lj9oyAMMwKIahhHHIZ33qOTq1c/9NtMVZmm/j4UfyCpP8WMAFb2hvwIJbjnAGO9Xbw+NzWaQdvEyNDGUX+bPIuSDc75jjGH5KtdFLopk5k6nsTdU26qLkVE6Mg9Y//s0OJCvmYFgfw15IXDb50xJupWxCwbqGXWmfTBEo9M9AhelVbOXkitZR7hbnT6BZnsfpS2acZRNL4XxC+gg4Ml9fOiYsGWqSK8Lkwlp22rtL70CIHnggbb+oIE4ObR4TV8qMIAGCSqGSIb3DQEHATAdBglghkgBZQMEASoEEEMr/6uiZK+CzgfJvr61JTGggAQwfp0W0Q/QPYmg6AoC3DkE5+beNswVOX9ct5IIgIsvaAhTF9IiHdbX7yLa8YS2WQ/FAAAAAAAAAAAAAA==";
    let cipher_text = STANDARD.decode(CIPHER_TEXT_STR).unwrap();

    let data = parse_enveloped_data(&cipher_text).unwrap();
    assert_eq!(
        data,
        ParsedEnvelopedData {
            cipher_key: vec![
                23, 154, 52, 226, 30, 152, 62, 57, 198, 26, 127, 98, 18, 104, 51, 105, 65, 193, 14,
                171, 173, 82, 155, 122, 222, 222, 255, 185, 207, 104, 89, 61, 239, 30, 161, 65,
                161, 152, 196, 186, 164, 43, 130, 248, 20, 86, 237, 26, 100, 143, 0, 218, 93, 12,
                243, 71, 248, 196, 198, 122, 218, 16, 68, 247, 150, 63, 104, 200, 3, 12, 192, 162,
                26, 134, 17, 199, 33, 157, 247, 168, 228, 234, 213, 207, 253, 54, 211, 21, 102,
                105, 191, 143, 133, 31, 200, 42, 79, 241, 99, 0, 21, 189, 161, 191, 2, 9, 110, 57,
                192, 24, 239, 87, 111, 15, 141, 205, 102, 144, 118, 241, 50, 52, 49, 148, 95, 230,
                207, 34, 228, 131, 115, 190, 99, 140, 97, 249, 42, 215, 69, 46, 138, 100, 230, 78,
                167, 177, 55, 84, 219, 170, 139, 145, 81, 58, 50, 15, 88, 255, 251, 52, 56, 144,
                175, 153, 129, 96, 127, 13, 121, 33, 112, 219, 231, 76, 73, 186, 149, 177, 11, 6,
                234, 25, 117, 166, 125, 48, 68, 163, 211, 61, 2, 23, 165, 85, 179, 151, 146, 43,
                89, 71, 184, 91, 157, 62, 129, 102, 123, 31, 165, 45, 154, 113, 148, 77, 47, 133,
                241, 11, 232, 32, 224, 201, 125, 124, 232, 152, 176, 101, 170, 72, 175, 11, 147, 9,
                105, 219, 106, 237, 47, 189, 2, 32, 121, 224, 129, 182, 254, 160, 129, 56, 57, 180,
                120, 77, 95, 42
            ],
            iv: vec![67, 43, 255, 171, 162, 100, 175, 130, 206, 7, 201, 190, 190, 181, 37, 49],
            cipher_text: vec![
                126, 157, 22, 209, 15, 208, 61, 137, 160, 232, 10, 2, 220, 57, 4, 231, 230, 222,
                54, 204, 21, 57, 127, 92, 183, 146, 8, 128, 139, 47, 104, 8, 83, 23, 210, 34, 29,
                214, 215, 239, 34, 218, 241, 132, 182, 89, 15, 197
            ]
        }
    );

    let private_key = rsa::RsaPrivateKey::from_pkcs1_pem(RSA_KEY).unwrap();
    let result = decrypt_cfr(&data, &private_key).unwrap();
    assert_eq!(
        result,
        vec![
            0x3b, 0xe8, 0x2c, 0x44, 0xf, 0x6, 0xcb, 0x4d, 0x44, 0xc4, 0xc2, 0xec, 0x3b, 0xf3, 0xd,
            0x47, 0x24, 0x7, 0xd3, 0xa9, 0x12, 0x5a, 0xa4, 0xc1, 0x84, 0x2b, 0x98, 0xf6, 0xbd,
            0xd2, 0x6e, 0x41,
        ]
    );
}
