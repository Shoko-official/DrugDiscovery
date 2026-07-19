use std::{error::Error, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let proto_root = manifest_dir.join("../../proto");
    let proto_file = proto_root.join("bioworld/v2/decision.proto");
    let vendored_include = protoc_bin_vendored::include_path()?;

    println!("cargo:rerun-if-changed={}", proto_file.display());

    let mut prost_config = tonic_prost_build::Config::new();
    prost_config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);

    tonic_prost_build::configure()
        .build_transport(false)
        .compile_with_config(prost_config, &[proto_file], &[proto_root, vendored_include])?;

    Ok(())
}
