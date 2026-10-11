use anyhow::{Result, anyhow, bail};

use crate::{BackwardsBuffer, Buffer, FOOTER_MAGIC, XZ_MAGIC};

use super::types::{Block, Checksum, Filter, IndexRecord, XZInfo};

pub fn parse<'a>(bytes: &'a mut Buffer) -> Result<XZInfo<'a>> {
    // Parse the front
    if bytes.get(XZ_MAGIC.len())? != XZ_MAGIC { bail!("File is not an XZ file!") }

    let stream_flag_bytes = bytes.get(2)?;

    let stream_flags_high = stream_flag_bytes[0];
    if stream_flags_high != 0 { bail!("Expected null byte in stream flags!") }

    let stream_flags_low = stream_flag_bytes[1];
    let checksum_alg = Checksum::from_stream_flags(stream_flags_low)?;

    let crc32 = crc_fast::crc32_iso_hdlc(stream_flag_bytes);
    let crc_bytes: &[u8; 4] = bytes.get(4)?.try_into()?;
    if u32::from_le_bytes(*crc_bytes) != crc32 { bail!("Failed to validate stream checksum!") }

    // Parse the back
    let mut iter = BackwardsBuffer::new(bytes.data());

    let footer_magic = iter.get(2)?;
    if footer_magic != FOOTER_MAGIC { bail!("Invalid footer magic!") }

    let footer_stream_flags = iter.get(2)?;
    if footer_stream_flags != stream_flag_bytes { bail!("Header and footer stream flags do not match!") }

    let backwards_size_bytes: &[u8; 4] = iter.get(4)?.try_into()?;
    let backwards_size = u32::from_le_bytes(*backwards_size_bytes);

    let crc_bytes: &[u8; 4] = iter.get(4)?.try_into()?;
    let crc_file = u32::from_le_bytes(*crc_bytes);
    let checksum = {
        let mut digest = crc_fast::Digest::new(crc_fast::CrcAlgorithm::Crc32IsoHdlc);
        digest.update(backwards_size_bytes);
        digest.update(footer_stream_flags);
        digest.finalize() as u32
    };

    if checksum != crc_file { bail!("Cannot validate footer checksum!") }

    let footer_start = iter.cursor;
    let index_offset = ((backwards_size as usize) + 1) * 4;
    let index_start = footer_start
        .checked_sub(index_offset)
        .ok_or_else(|| anyhow!("Backward size exceeds stream!"))?;

    // Parse the index
    let mut iter = bytes.child(index_start)?;

    if iter.next_val()? != 0x00 { bail!("Invalid index start!") }
    let count = decode_number(&mut iter)? as usize;
    let mut records: Vec<IndexRecord> = Vec::with_capacity(count);

    for _ in 0..count {
        let unpadded_size = decode_number(&mut iter)?;
        if unpadded_size == 0 { bail!("Failed to parse index entry!") }
        let uncompressed_size = decode_number(&mut iter)?;

        records.push(IndexRecord {unpadded_size, uncompressed_size});
    }

    let padding = iter.cursor.next_multiple_of(4) - iter.cursor;
    for &b in iter.get(padding)? { if b != 0 { bail!("Expected padding to be null!") } }

    let crc_bytes: [u8; 4] = iter.get(4)?.try_into()?;
    let crc32 = u32::from_le_bytes(crc_bytes);

    let checksum_data = &iter.data()[..iter.cursor - 4];
    if crc_fast::crc32_iso_hdlc(checksum_data) != crc32 { bail!("Cannot verify index checksum!") }

    // Parse blocks
    let mut blocks: Vec<Block> = Vec::new();
    let mut offset = 0;

    for record in records {
        let block_start = bytes.cursor;
        let block_size = bytes.next_val()?;

        if block_size == 0 { bail!("Block start is a null byte!") }

        let actual_size = (block_size as usize + 1) * 4;

        let block_flags = bytes.next_val()?;
        if block_flags & 0x3C != 0 { bail!("Invalid block flags!") }

        let filter_count = (block_flags & 3) + 1;
        let c_size_present = (block_flags & 0x40) != 0;
        let uc_size_present = (block_flags & 0x80) != 0;

        let mut comp_size: Option<u64> = None;
        let mut ucomp_size: Option<u64> = None;

        if c_size_present { comp_size = Some(decode_number(bytes)?); };
        if uc_size_present { ucomp_size = Some(decode_number(bytes)?); };

        // Parse filters
        let mut filters: Vec<Filter> = Vec::with_capacity(filter_count as usize);

        for _ in 0..filter_count {
            let filter_id = decode_number(bytes)?;
            let prop_size = decode_number(bytes)?;
            let properties = bytes.get(prop_size as usize)?;

            filters.push(Filter::new(filter_id, properties)?);
        }

        let padding = (block_start + actual_size)
            .checked_sub(bytes.cursor + 4)
            .ok_or_else(|| anyhow!("Invalid padding size!"))?;

        for &b in bytes.get(padding)? { if b != 0 { bail!("Expected null byte in padding!") } }

        let checksum_data = &bytes.data[block_start..bytes.cursor];
        let crc_bytes: &[u8; 4] = bytes.get(4)?.try_into()?;
        let crc32 = u32::from_le_bytes(*crc_bytes);

        if crc_fast::crc32_iso_hdlc(checksum_data) != crc32 { bail!("Failed to validate block checksum!") }

        let compressed_size = record
            .unpadded_size
            .checked_sub(actual_size as u64)
            .and_then(|v| v.checked_sub(checksum_alg.size() as u64))
            .ok_or_else(|| anyhow!("Unpadded block too small for block!"))?;

        if let Some(c) = comp_size && c != compressed_size { bail!("Index and block data do not agree!") }
        if let Some(uc) = ucomp_size && uc != record.uncompressed_size { bail!("Index and block data do not agree!") }
     
        let data = bytes.get(compressed_size as usize)?;

        let padding = bytes.cursor.next_multiple_of(4) - bytes.cursor;
        for &b in bytes.get(padding)? { if b != 0 { bail!("Expected null byte in padding!") } }

        let check = bytes.get(checksum_alg.size())?;

        blocks.push(Block { filters, compressed_size, uncompressed_size: record.uncompressed_size, data, check, offset });
        offset += record.uncompressed_size;
    }

    if bytes.cursor != index_start { bail!("Invalid block and index addresses") }

    Ok(XZInfo { checksum_alg, blocks })
}

pub fn decode_number(bytes: &mut Buffer) -> Result<u64> {
    let mut res = 0;
    let mut i = 0;
    let mut check_next = false;

    while i < 9 {
        let byte = bytes.next_val()?;
        if byte == 0x00 && check_next { bail!("Failed to parse number!") }

        check_next = byte > 0x7F;
        let val = byte & 0x7F;
        res |= (val as u64) << (i * 7);

        if i == 8 && check_next { bail!("Failed to parse number!") }
        if !check_next { break }

        i += 1;
    }

    Ok(res)
}
