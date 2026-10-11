mod filters;
mod parse;
mod types;

use std::{borrow::Cow, fs::File, os::unix::fs::FileExt};

use anyhow::{Result, bail};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use sha2::Digest;

use crate::Buffer;

use self::types::{Block, Checksum};

pub fn decompress(bytes: &mut Buffer, out: &File) -> Result<()> {
    let info = parse::parse(bytes)?;

    info.blocks
        .into_par_iter()
        .try_for_each(|b| {
            let offset = b.offset;
            let data = decode_block(b, &info.checksum_alg)?;
            out.write_all_at(&data, offset)?;
            Result::<(), anyhow::Error>::Ok(())
        })?;
        

    Ok(())
}

fn decode_block<'a>(block: Block<'a>, checksum_alg: &Checksum) -> Result<Cow<'a, [u8]>> {
    let size = block.uncompressed_size as usize;
    let mut data = Cow::Borrowed(block.data);

    for filter in block.filters.into_iter().rev() {
        data = Cow::Owned(filters::decode_filter(&data, filter, size)?);
    }

    let checksum: &[u8] = match checksum_alg {
        types::Checksum::Crc32 => &crc_fast::crc32_iso_hdlc(&data).to_le_bytes(),
        types::Checksum::Crc64 => &crc_fast::checksum(crc_fast::CrcAlgorithm::Crc64Xz, &data).to_le_bytes(),
        types::Checksum::None => &[],
        types::Checksum::Sha256 => &sha2::Sha256::digest(&data)
    };

    if checksum != block.check { bail!("Failed to verify block checksum!") }

    Ok(data)
}