use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::Context as _;
use clap::Parser;

use crate::build_ebpf::{build_ebpf, Architecture, Options as BuildOptions};

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    #[clap(long)]
    pub release: bool,
    #[clap(default_value = "eth0", long)]
    pub intf: String,
    #[clap(default_value = "archlinux", long)]
    pub image: String,
}

fn project_root() -> PathBuf {
    Path::new(&env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf()
}

/// Build the project
fn build(opts: &Options) -> Result<(), anyhow::Error> {
    let mut args = vec!["build"];
    if opts.release {
        args.push("--release")
    }
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}

/// Build and run the project
pub fn run_docker(opts: Options) -> Result<(), anyhow::Error> {
    // build our ebpf program followed by our application
    build_ebpf(BuildOptions {
        target: opts.bpf_target,
        release: opts.release,
    })
    .context("Error while building eBPF program")?;
    build(&opts).context("Error while building userspace application")?;

    // profile we are building (release or debug)
    let profile = if opts.release { "release" } else { "debug" };
    let bin_path = format!("target/{profile}/loader");

    let args = vec![
        "run",
        "--privileged",
        "-e",
        "RUST_LOG=info",
        "-v",
        "./target:/target",
        "-it",
        &opts.image,
        &bin_path,
        "-i",
        &opts.intf,
    ];

    // run the command inside a docker container
    let status = Command::new("docker")
        .current_dir(project_root())
        .args(&args)
        .status()
        .expect("failed to run docker container");
    assert!(status.success());
    Ok(())
}
