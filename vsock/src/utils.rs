use std::io::{Error, Result};
use std::mem::zeroed;
use std::os::fd::{FromRawFd, OwnedFd};

pub fn libc_ret<T: num::Signed>(v: T) -> Result<T> {
    if v.is_negative() {
        Err(Error::last_os_error())
    } else {
        Ok(v)
    }
}

macro_rules! decl_geter {
    ($name:ident, $libc_fn:path, $libc_ty:path, $($a:ident: $t:path),*) => {
        pub fn $name<T>($($a: $t),*) -> Result<T> {
            let mut value: T = unsafe { zeroed() };
            let mut value_len = size_of::<T>() as libc::socklen_t;
            libc_ret(unsafe {
                $libc_fn(
                    $($a),*,
                    &mut value as *mut T as *mut $libc_ty,
                    &mut value_len as *mut libc::socklen_t,
                )
            })?;
            Ok(value)
        }
    };
}

macro_rules! decl_setter {
    ($name:ident, $libc_fn:path, $libc_ty:path, $($a:ident: $t:path),*) => {
        pub fn $name<T>($($a: $t),*, val: &T) -> Result<()> {
            libc_ret(unsafe {
                $libc_fn(
                    $($a),*,
                    val as *const T as *const $libc_ty,
                    size_of::<T>() as libc::socklen_t,
                )
            }).and(Ok(()))
        }
    };
}

decl_geter!(getsockopt, libc::getsockopt, libc::c_void, socket: libc::c_int, level: libc::c_int, name: libc::c_int);
decl_geter!(getsockname, libc::getsockname, libc::sockaddr, socket: libc::c_int);
decl_geter!(getpeername, libc::getpeername, libc::sockaddr, socket: libc::c_int);

decl_setter!(setsockopt, libc::setsockopt, libc::c_void, socket: libc::c_int, level: libc::c_int, name: libc::c_int);
decl_setter!(bind, libc::bind, libc::sockaddr, socket: libc::c_int);
decl_setter!(connect, libc::connect, libc::sockaddr, socket: libc::c_int);

pub fn socket(domain: libc::c_int, ty: libc::c_int, protocol: libc::c_int) -> Result<OwnedFd> {
    Ok(unsafe { OwnedFd::from_raw_fd(libc_ret(libc::socket(domain, ty, protocol))?) })
}

pub fn recvfrom<T>(socket: libc::c_int, buf: &mut [u8], flags: libc::c_int) -> Result<(usize, T)> {
    let mut addr: T = unsafe { zeroed() };
    let mut addr_len = size_of::<T>() as libc::socklen_t;

    libc_ret(unsafe {
        libc::recvfrom(
            socket,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            flags,
            &mut addr as *mut T as *mut libc::sockaddr,
            &mut addr_len as *mut libc::socklen_t,
        )
    })
    .map(|len| (len as usize, addr))
}

pub fn sendto<T>(socket: libc::c_int, buf: &[u8], flags: libc::c_int, addr: &T) -> Result<usize> {
    libc_ret(unsafe {
        libc::sendto(
            socket,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            flags,
            addr as *const T as *const libc::sockaddr,
            size_of::<T>() as libc::socklen_t,
        )
    })
    .map(|x| x as usize)
}

pub fn listen(socket: libc::c_int, backlog: libc::c_int) -> Result<()> {
    libc_ret(unsafe { libc::listen(socket, backlog) }).and(Ok(()))
}

pub fn accept<T>(socket: libc::c_int) -> Result<(OwnedFd, T)> {
    let mut addr: T = unsafe { zeroed() };
    let mut addr_len = size_of::<T>() as libc::socklen_t;

    unsafe {
        libc_ret(libc::accept(
            socket,
            &mut addr as *mut T as *mut libc::sockaddr,
            &mut addr_len as *mut libc::socklen_t,
        ))
        .map(|s| (OwnedFd::from_raw_fd(s), addr))
    }
}

pub fn recv(socket: libc::c_int, buf: &mut [u8]) -> Result<usize> {
    libc_ret(unsafe { libc::recv(socket, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) })
        .map(|x| x as usize)
}

pub fn send(socket: libc::c_int, buf: &[u8]) -> Result<usize> {
    libc_ret(unsafe { libc::send(socket, buf.as_ptr() as *const libc::c_void, buf.len(), 0) })
        .map(|x| x as usize)
}

pub fn fcntl(socket: libc::c_int, cmd: libc::c_int, arg: libc::c_int) -> Result<libc::c_int> {
    libc_ret(unsafe { libc::fcntl(socket, cmd, arg) })
}

pub fn shutdown(socket: libc::c_int, how: libc::c_int) -> Result<()> {
    libc_ret(unsafe { libc::shutdown(socket, how) }).and(Ok(()))
}
