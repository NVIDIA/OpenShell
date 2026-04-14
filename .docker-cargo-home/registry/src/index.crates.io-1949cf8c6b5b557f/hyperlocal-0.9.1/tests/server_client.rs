use http_body_util::{BodyExt, Full};
use std::{error::Error, fs, path::Path};

use hyper::{body::Bytes, service::service_fn, Response};
use hyper_util::{client::legacy::Client, rt::TokioIo};
use hyperlocal::{UnixClientExt, UnixConnector, Uri};
use tokio::net::UnixListener;

const PHRASE: &str = "It works!";

#[derive(Debug, thiserror::Error)]
enum ListenerError {
    #[error("Failed to accept connection: {0}")]
    Accepting(std::io::Error),

    #[error("Failed to serve connection: {0}")]
    Serving(hyper::Error),
}

#[tokio::test]
async fn test_server_client() -> Result<(), Box<dyn Error + Send + Sync>> {
    let path = Path::new("/tmp/hyperlocal.sock");

    if path.exists() {
        fs::remove_file(path)?;
    }

    let svc_fn =
        service_fn(|_req| async { Ok::<_, hyper::Error>(Response::new(PHRASE.to_string())) });

    let listener = UnixListener::bind(path)?;

    let _server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.map_err(ListenerError::Accepting)?;

        let io = TokioIo::new(stream);

        hyper::server::conn::http1::Builder::new()
            .serve_connection(io, svc_fn)
            .await
            .map_err(ListenerError::Serving)
    });

    let client: Client<UnixConnector, Full<Bytes>> = Client::unix();

    let url = Uri::new(path, "/").into();

    let mut response = client.get(url).await?;
    let mut bytes = Vec::default();

    while let Some(frame_result) = response.frame().await {
        let frame = frame_result?;

        if let Some(segment) = frame.data_ref() {
            bytes.extend(segment.iter().as_slice());
        }
    }

    let string = String::from_utf8(bytes)?;

    assert_eq!(PHRASE, string);

    Ok(())
}
