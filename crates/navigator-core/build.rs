use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use bundled protoc from protobuf-src
    // SAFETY: This is run at build time in a single-threaded build script context.
    // No other threads are reading environment variables concurrently.
    #[allow(unsafe_code)]
    unsafe {
        env::set_var("PROTOC", protobuf_src::protoc());
    }

    let proto_files = [
        "../../proto/navigator.proto",
        "../../proto/datamodel.proto",
        "../../proto/sandbox.proto",
        "../../proto/inference.proto",
        "../../proto/test.proto",
    ];

    // Configure tonic-build
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&proto_files, &["../../proto"])?;

    // Tell cargo to rerun if the proto file changes
    for proto_file in proto_files {
        println!("cargo:rerun-if-changed={proto_file}");
    }

    Ok(())
}
