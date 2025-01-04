pub use aws_nitro_enclaves_nsm_api::api::{ErrorCode, Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_init, nsm_process_request};
use rsa::pkcs8::{spki, EncodePublicKey};
use std::{
    alloc::{alloc, dealloc, Layout},
    cmp, fs, io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub struct NSM(OwnedFd);

impl NSM {
    pub fn open() -> Result<Self, Error> {
        let fd = nsm_init();
        if fd < 0 {
            Err(Error::IO(io::Error::last_os_error()))
        } else {
            Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
        }
    }

    pub fn attest(
        &self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&rsa::RsaPublicKey>,
    ) -> Result<Vec<u8>, Error> {
        let pk = match public_key {
            // SubjectPublicKeyInfo (RFC 5280)
            Some(key) => Some(key.to_public_key_der()?.into_vec()),
            None => None,
        };

        let req = Request::Attestation {
            user_data: user_data.map(|v| Vec::from(v).into()),
            nonce: nonce.map(|v| Vec::from(v).into()),
            public_key: pk.map(Into::into),
        };

        match nsm_process_request(self.0.as_raw_fd(), req) {
            Response::Attestation { document } => Ok(document),
            Response::Error(error_code) => Err(Error::NSM(error_code)),
            _ => Err(Error::ResponseType),
        }
    }

    pub fn get_random_vec(&self) -> Result<Vec<u8>, Error> {
        match nsm_process_request(self.0.as_raw_fd(), Request::GetRandom) {
            Response::GetRandom { random } => Ok(random),
            Response::Error(error_code) => Err(Error::NSM(error_code)),
            _ => Err(Error::ResponseType),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    IO(io::Error),
    NSM(ErrorCode),
    SPKI(spki::Error),
    ResponseType,
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Error::IO(value)
    }
}

impl From<spki::Error> for Error {
    fn from(value: spki::Error) -> Self {
        Error::SPKI(value)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IO(error) => write!(f, "IO error: {}", error),
            Error::NSM(error_code) => match error_code {
                ErrorCode::Success => f.write_str("NSM error: success"),
                ErrorCode::InvalidArgument => f.write_str("NSM error: invalid argument"),
                ErrorCode::InvalidIndex => f.write_str("NSM error: invalid index"),
                ErrorCode::InvalidResponse => f.write_str("NSM error: invalid response"),
                ErrorCode::ReadOnlyIndex => f.write_str("NSM error: read_only index"),
                ErrorCode::InvalidOperation => f.write_str("NSM error: invalid operation"),
                ErrorCode::BufferTooSmall => f.write_str("NSM error: buffer too small"),
                ErrorCode::InputTooLarge => f.write_str("NSM error: input too large"),
                ErrorCode::InternalError => f.write_str("NSM error: internal error"),
            },
            Error::SPKI(error) => write!(f, "SPKI error: {}", error),
            Error::ResponseType => f.write_str("wrong response type"),
        }
    }
}

const RNDADDENTROPY: libc::c_ulong = 0x40085203;

#[repr(C)]
struct RandPoolInfo {
    entropy_count: libc::c_int,
    buf_size: libc::c_int,
    buf: [u32; 0],
}

unsafe fn rnd_add_entropy(fd: libc::c_int, bytes: &[u8]) -> Result<(), io::Error> {
    let layout = Layout::from_size_align_unchecked(
        mem::size_of::<RandPoolInfo>() + bytes.len(),
        mem::align_of::<RandPoolInfo>(),
    );
    let ptr = alloc(layout);

    let info: &mut RandPoolInfo = &mut *(ptr as *mut RandPoolInfo);
    info.entropy_count = (bytes.len() * 8) as libc::c_int;
    info.buf_size = bytes.len() as libc::c_int;

    ptr.add(mem::size_of::<RandPoolInfo>())
        .copy_from_nonoverlapping(bytes.as_ptr(), bytes.len());

    let ret = libc::ioctl(fd, RNDADDENTROPY, ptr as *const RandPoolInfo);
    dealloc(ptr, layout);
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub const DEFAULT_ENTROPY_BYTE_SZ: usize = 1024;

pub fn seed_rng(nsm: &NSM, mut bytes: usize) -> Result<(), Error> {
    const DEV_RANDOM: &str = "/dev/random";

    let fd = fs::OpenOptions::new().write(true).open(DEV_RANDOM)?;
    while bytes != 0 {
        let chunk = nsm.get_random_vec()?;
        if chunk.len() == 0 {
            return Err(Error::NSM(ErrorCode::InternalError));
        }
        let sz = cmp::min(chunk.len(), bytes);
        unsafe { rnd_add_entropy(fd.as_raw_fd(), &chunk[0..sz]) }?;
        bytes -= sz;
    }
    Ok(())
}
