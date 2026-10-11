use std::{fs::File, path::PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use rip_xz::Buffer;

#[derive(Debug, Parser)]
#[command(version, author, about)]
struct Args {
    #[command(subcommand)]
    command: Command
}

#[derive(Debug, Subcommand)]
enum Command {
    Decompress {
        input: PathBuf,
        output: PathBuf
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Decompress { input, output } => {
            let data = std::fs::read(input)?;
            let mut file = File::create(output)?;

            rip_xz::decompress(&mut Buffer::new(&data), &mut file)?;
        }
    }

    Ok(())
}

// ❯ hyperfine "xz -dkf tests/test-large.xz" -N
// Benchmark 1: xz -dkf tests/test-large.xz
//   Time (mean ± σ):       7.8 ms ±   0.8 ms    [User: 2.0 ms, System: 8.3 ms]
//   Range (min … max):     5.2 ms …  10.2 ms    352 runs
 
// ❯ hyperfine "target/release/rip-xz decompress tests/test-large.xz test-large" -N
// Benchmark 1: target/release/rip-xz decompress tests/test-large.xz test-large
//   Time (mean ± σ):       8.6 ms ±   1.2 ms    [User: 1.9 ms, System: 6.3 ms]
//   Range (min … max):     6.8 ms …  13.6 ms    288 runs
