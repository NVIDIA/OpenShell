use openssh::*;

#[tokio::main]
async fn main() {
    let session = Session::connect_mux("ssh://jon@ssh.thesquareplanet.com:222", KnownHosts::Strict)
        .await
        .unwrap();

    let ls = session.command("ls").output().await.unwrap();
    eprintln!(
        "{}",
        String::from_utf8(ls.stdout).expect("server output was not valid UTF-8")
    );

    let whoami = session.command("whoami").output().await.unwrap();
    assert_eq!(whoami.stdout, b"jon\n");

    session.close().await.unwrap();
}
