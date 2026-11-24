//! Compiles the `.proto` files with `protox` (pure Rust), so building needs no
//! system `protoc`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const FILES: &[&str] = &[
        "proto/zd/v1/common.proto",
        "proto/zd/v1/keys.proto",
        "proto/zd/v1/detect.proto",
        "proto/zd/v1/address.proto",
        "proto/zd/v1/spend.proto",
    ];
    for f in FILES {
        println!("cargo:rerun-if-changed={f}");
    }
    let fds = protox::compile(FILES, ["proto"])?;
    tonic_prost_build::configure().compile_fds(fds)?;
    Ok(())
}
