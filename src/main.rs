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
            let file = File::create(output)?;

            rip_xz::decompress(&mut Buffer::new(&data), &file)?;
        }
    }

    Ok(())
}
