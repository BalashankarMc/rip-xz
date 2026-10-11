mod parse;

use std::fs::File;

use anyhow::Result;

use crate::Buffer;

/// Decompress the provided buffer into the given file
pub fn decompress(input: &mut Buffer, output: &File) -> Result<()> {
    let info = parse::parse(input)?; 
    Ok(())
}