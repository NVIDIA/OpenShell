use hyper::Uri as HyperUri;
use log::trace;
use url::Url;

use std::borrow::Cow;
use std::ffi::OsStr;

use crate::docker::{ClientType, ClientVersion};
use crate::errors::Error;

#[derive(Debug)]
pub struct Uri<'a> {
    encoded: Cow<'a, str>,
}

impl<'a> TryFrom<Uri<'a>> for HyperUri {
    type Error = http::uri::InvalidUri;

    fn try_from(uri: Uri<'a>) -> Result<Self, Self::Error> {
        uri.encoded.as_ref().parse()
    }
}

impl<'a> Uri<'a> {
    pub(crate) fn parse<O>(
        socket: &'a str,
        client_type: &ClientType,
        path: &'a str,
        query: Option<O>,
        client_version: &ClientVersion,
    ) -> Result<Self, Error>
    where
        O: serde::ser::Serialize,
    {
        let host_str = format!(
            "{}://{}/v{}.{}{}",
            Uri::socket_scheme(client_type),
            Uri::socket_host(socket, client_type),
            client_version.major_version,
            client_version.minor_version,
            path
        );
        let mut url = Url::parse(host_str.as_ref())?;
        url = url.join(path)?;

        if let Some(pairs) = query {
            trace!("pairs: {}", serde_json::to_string(&pairs)?);

            let qs = serde_urlencoded::to_string(pairs)?;
            url.set_query(Some(&qs));
        }

        trace!(
            "Parsing uri: {}, client_type: {:?}, socket: {}",
            url.as_str(),
            client_type,
            socket
        );
        Ok(Uri {
            encoded: Cow::Owned(url.as_str().to_owned()),
        })
    }

    fn socket_host<P>(socket: P, client_type: &ClientType) -> String
    where
        P: AsRef<OsStr>,
    {
        match client_type {
            #[cfg(feature = "http")]
            ClientType::Http => socket.as_ref().to_string_lossy().into_owned(),
            #[cfg(feature = "ssl_providerless")]
            ClientType::SSL => socket.as_ref().to_string_lossy().into_owned(),
            #[cfg(all(feature = "pipe", unix))]
            ClientType::Unix => hex::encode(socket.as_ref().to_string_lossy().as_bytes()),
            #[cfg(all(feature = "pipe", windows))]
            ClientType::NamedPipe => hex::encode(socket.as_ref().to_string_lossy().as_bytes()),
            #[cfg(feature = "ssh")]
            ClientType::Ssh => socket.as_ref().to_string_lossy().into_owned(),
            ClientType::Custom { .. } => socket.as_ref().to_string_lossy().into_owned(),
        }
    }

    fn socket_scheme(client_type: &'a ClientType) -> &'a str {
        match client_type {
            #[cfg(feature = "http")]
            ClientType::Http => "http",
            #[cfg(feature = "ssl_providerless")]
            ClientType::SSL => "https",
            #[cfg(all(feature = "pipe", unix))]
            ClientType::Unix => "unix",
            #[cfg(all(feature = "pipe", windows))]
            ClientType::NamedPipe => "net.pipe",
            #[cfg(feature = "ssh")]
            ClientType::Ssh => "ssh",
            ClientType::Custom { scheme } => scheme.as_str(),
        }
    }
}
