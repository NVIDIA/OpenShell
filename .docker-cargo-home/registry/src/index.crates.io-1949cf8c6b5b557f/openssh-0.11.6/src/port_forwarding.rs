#[cfg(feature = "native-mux")]
use super::native_mux_impl;

#[cfg(feature = "process-mux")]
use std::ffi::OsStr;

use std::borrow::Cow;
use std::fmt;
use std::net::{self, IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

/// Type of forwarding
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ForwardType {
    /// Forward requests to a port on the local machine to remote machine.
    Local,

    /// Forward requests to a port on the remote machine to local machine.
    Remote,
}

#[cfg(feature = "native-mux")]
impl From<ForwardType> for native_mux_impl::ForwardType {
    fn from(fwd_type: ForwardType) -> Self {
        use native_mux_impl::ForwardType::*;

        match fwd_type {
            ForwardType::Local => Local,
            ForwardType::Remote => Remote,
        }
    }
}

/// TCP/Unix socket
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Socket<'a> {
    /// Unix socket.
    #[cfg(unix)]
    #[cfg_attr(docsrs, doc(cfg(unix)))]
    UnixSocket {
        /// Filesystem path
        path: Cow<'a, Path>,
    },

    /// Tcp socket.
    TcpSocket {
        /// Hostname.
        host: Cow<'a, str>,
        /// Port.
        port: u16,
    },
}

impl From<SocketAddr> for Socket<'static> {
    fn from(addr: SocketAddr) -> Self {
        let host = match addr.ip() {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        };
        Socket::TcpSocket {
            host: host.into(),
            port: addr.port(),
        }
    }
}

macro_rules! impl_from_addr {
    ($ip:ty) => {
        impl From<($ip, u16)> for Socket<'static> {
            fn from((ip, port): ($ip, u16)) -> Self {
                SocketAddr::new(ip.into(), port).into()
            }
        }
    };
}

impl_from_addr!(net::IpAddr);
impl_from_addr!(net::Ipv4Addr);
impl_from_addr!(net::Ipv6Addr);

impl<'a> From<Cow<'a, Path>> for Socket<'a> {
    fn from(path: Cow<'a, Path>) -> Self {
        Socket::UnixSocket { path }
    }
}

impl<'a> From<&'a Path> for Socket<'a> {
    fn from(path: &'a Path) -> Self {
        Socket::UnixSocket {
            path: Cow::Borrowed(path),
        }
    }
}

impl From<PathBuf> for Socket<'static> {
    fn from(path: PathBuf) -> Self {
        Socket::UnixSocket {
            path: Cow::Owned(path),
        }
    }
}

impl From<Box<Path>> for Socket<'static> {
    fn from(path: Box<Path>) -> Self {
        Socket::UnixSocket {
            path: Cow::Owned(path.into()),
        }
    }
}

impl Socket<'_> {
    /// Create a new TcpSocket
    pub fn new<'a, S>(host: S, port: u16) -> Socket<'a>
    where
        S: Into<Cow<'a, str>>,
    {
        Socket::TcpSocket {
            host: host.into(),
            port,
        }
    }

    #[cfg(feature = "process-mux")]
    pub(crate) fn as_os_str(&self) -> Cow<'_, OsStr> {
        match self {
            #[cfg(unix)]
            Socket::UnixSocket { path } => Cow::Borrowed(path.as_os_str()),
            Socket::TcpSocket { host, port } => Cow::Owned(format!("{host}:{port}").into()),
        }
    }
}

#[cfg(feature = "native-mux")]
impl<'a> From<Socket<'a>> for native_mux_impl::Socket<'a> {
    fn from(socket: Socket<'a>) -> Self {
        use native_mux_impl::Socket::*;

        match socket {
            #[cfg(unix)]
            Socket::UnixSocket { path } => UnixSocket { path },
            Socket::TcpSocket { host, port } => TcpSocket {
                host,
                port: port as u32,
            },
        }
    }
}

impl<'a> fmt::Display for Socket<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(unix)]
            Socket::UnixSocket { path } => {
                write!(f, "{}", path.display())
            }
            Socket::TcpSocket { host, port } => write!(f, "{host}:{port}"),
        }
    }
}
