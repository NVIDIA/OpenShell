use std::{error::Error, fs, path::Path};

use hyper::Response;
use tokio::net::UnixListener;

use hyperlocal::UnixListenerExt;

const PHRASE: &str = "It's a Unix system. I know this.\n";

// Adapted from https://hyper.rs/guides/1/server/hello-world/
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let path = Path::new("/tmp/hyperlocal.sock");

    if path.exists() {
        fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;

    println!("Listening for connections at {}.", path.display());

    listener
        .serve(|| {
            println!("Accepted connection.");

            |_request| async {
                let body = PHRASE.to_string();
                Ok::<_, hyper::Error>(Response::new(body))
            }
        })
        .await?;

    Ok(())
}
