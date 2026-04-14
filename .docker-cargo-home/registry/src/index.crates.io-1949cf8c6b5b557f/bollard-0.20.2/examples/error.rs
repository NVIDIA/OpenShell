/// Example of using `std::error::Error` with bollard
extern crate bollard;

use bollard::Docker;

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let _docker = Docker::connect_with_socket_defaults().unwrap();

    let _env_var = std::env::var("ZOOKEEPER_ADDR")?;

    Ok(())
}

fn main() {
    run().unwrap();
}
