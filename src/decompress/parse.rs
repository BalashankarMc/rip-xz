use anyhow::{Result, anyhow, bail};

use crate::{BackwardsBuffer, Buffer, FOOTER_MAGIC, XZ_MAGIC, checksums::crc32};

#[derive(Debug)]
pub struct XZInfo<'a> {
    pub checksum_alg: ChecksumAlg,
    pub blocks: Vec<Block<'a>>
}

#[derive(Debug)]
pub struct BlockInfo {
    pub unpadded_size: u64,
    pub uncompressed_size: u64
}


#[derive(Debug)]
pub enum FilterType {
    LZMA2,
    Delta,
    X86,
    PowerPC,
    IA64,
    Arm,
    ArmThumb,
    Sparc,
    Arm64,
    RiscV
}

impl FilterType {
    fn from_id(id: u64) -> Result<Self> {
        match id {
            0x03 => Ok(Self::Delta),
            0x04 => Ok(Self::X86),
            0x05 => Ok(Self::PowerPC),
            0x06 => Ok(Self::IA64),
            0x07 => Ok(Self::Arm),
            0x08 => Ok(Self::ArmThumb),
            0x09 => Ok(Self::Sparc),
            0x0A => Ok(Self::Arm64),
            0x0B => Ok(Self::RiscV),
            0x21 => Ok(Self::LZMA2),
            _ => bail!("Invalid filter id!")
        }
    }
}

#[derive(Debug)]
pub struct Filter<'a> {
    pub filter_type: FilterType,
    pub properties: &'a [u8]
}

impl<'a> Filter<'a> {
    pub fn new(id: u64, properties: &'a [u8]) -> Result<Self> {
        let filter_type = FilterType::from_id(id)?;

        let len = properties.len();
        let is_correct = match filter_type {
            FilterType::LZMA2 | FilterType::Delta => len == 1,
            _ => len == 0 || len == 4
        };

        if !is_correct { bail!("Invalid properties length!") }

        Ok(Self { filter_type, properties })
    }
}

#[derive(Debug)]
pub struct Block<'a> {
    pub offset: u64,
    pub filters: Vec<Filter<'a>>,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub data: &'a [u8],
    pub check: &'a [u8]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumAlg {
    None,
    CRC32,
    CRC64,
    SHA256
}

impl ChecksumAlg {
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0x0 => Some(Self::None),
            0x1 => Some(Self::CRC32),
            0x4 => Some(Self::CRC64),
            0xA => Some(Self::SHA256),
            _ => None
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Self::None => 0,
            Self::CRC32 => 4,
            Self::CRC64 => 8,
            Self::SHA256 => 32
        }
    }
}

/// Parse the given input into an XZInfo
pub fn parse<'a>(input: &mut Buffer<'a>) -> Result<XZInfo<'a>> {
    let (checksum_alg, stream_flags) = parse_header(input)?;
    let index_start = parse_footer(input, stream_flags)?;
    let block_info = parse_index(&mut input.child(index_start as usize)?)?;
    let blocks = parse_blocks(input, block_info, checksum_alg.size())?;

    Ok(XZInfo { checksum_alg, blocks })
}

/// Parse the header and return the checksum algorithm used and the raw stream flags for validating the footer
fn parse_header<'a>(input: &mut Buffer<'a>) -> Result<(ChecksumAlg, &'a [u8])> {
    if input.get(6)? != XZ_MAGIC { bail!("File is not an XZ File") }
    
    let stream_flag_bytes = input.get(2)?;
    if stream_flag_bytes[0] != 0 { bail!("Invalid stream bytes!") }

    let checksum_alg = ChecksumAlg::from_id(stream_flag_bytes[1])
        .ok_or_else(|| anyhow!("Invalid stream flags!"))?;

    let crc_from_file: &[u8; 4] = input.get(4)?.try_into()?;
    let crc32_from_file = u32::from_le_bytes(*crc_from_file);

    if crc32(stream_flag_bytes) != crc32_from_file { bail!("Failed to validate header magic!") }

    Ok((checksum_alg, stream_flag_bytes))
}

/// Parse the footer and return the (absolute) start of the index
fn parse_footer(input: &mut Buffer, stream_flags_bytes: &[u8]) -> Result<u64> {
    // Iterate backwards
    let mut input = BackwardsBuffer::new(input.data());

    if input.get(2)? != FOOTER_MAGIC { bail!("Failed to validate footer magic!") }

    let start = input.cursor;
    if input.get(2)? != stream_flags_bytes { bail!("Stream flags from the header and footer do not match!") }

    let backwards_size_bytes: &[u8; 4] = input.get(4)?.try_into()?;
    let backwards_size = u32::from_le_bytes(*backwards_size_bytes);
    let end = input.cursor;

    let crc_bytes: &[u8; 4] = input.get(4)?.try_into()?;
    let crc32_from_file = u32::from_le_bytes(*crc_bytes);
    let checksum_data = &input.data[end..start];
    if crc32(checksum_data) != crc32_from_file { bail!("Failed to verify footer checksum!") }

    let footer_start = input.cursor as u64;
    let index_offset = ((backwards_size as u64) + 1) * 4;
    let index_start = footer_start
        .checked_sub(index_offset)
        .ok_or_else(|| anyhow!("Backwards size exceeds stream!"))?;

    Ok(index_start)
}

// Parse the index and return the info for each block
pub fn parse_index(input: &mut Buffer) -> Result<Vec<BlockInfo>> {
    if input.next_val()? != 0 { bail!("Invalid index header!") }

    let record_count = decode_number(input)?;
    let mut records: Vec<BlockInfo> = Vec::with_capacity(record_count.min(256) as usize);

    for _ in 0..record_count {
        let unpadded_size = decode_number(input)?;
        let uncompressed_size = decode_number(input)?;

        records.push(BlockInfo { unpadded_size, uncompressed_size });
    }
    
    // The spec dictates that padding will be present to ensure index records
    // start at a multiple of 4.

    // The spec also states that the padding MUST be null bytes (0x00) but
    // this is not enforced here
    input.cursor = input.cursor.next_multiple_of(4);

    let crc_bytes: &[u8; 4] = input.get(4)?.try_into()?;
    let crc32_file = u32::from_le_bytes(*crc_bytes);
    let checksum_data = &input.data()[..input.cursor - 4];
    if crc32(checksum_data) != crc32_file { bail!("Cannot verify index checksum!") }

    Ok(records)
}

/// Parse the blocks and return the parsed `Block` struct
pub fn parse_blocks<'a>(input: &mut Buffer<'a>, block_info: Vec<BlockInfo>, check_size: usize) -> Result<Vec<Block<'a>>> {
    let mut res = Vec::new();
    let mut offset = 0;

    for block_info in block_info {
        let start = input.cursor;

        let block_header = input.next_val()? as usize;
        if block_header == 0 { bail!("Invalid block header size!") }
        let actual_size = (block_header + 1) * 4;

        let block_flags = input.next_val()?;
        if block_flags & 0x3C != 0 { bail!("Invalid block flags!") }
        let filter_count = (block_flags & 3) + 1;
        let csize_present = (block_flags & 0x40) != 0;
        let ucsize_present = (block_flags & 0x80) != 0;

        if csize_present { let _ = decode_number(input)?; }

        if ucsize_present {
            let uc_size = decode_number(input)?;
            if uc_size != block_info.uncompressed_size { bail!("Index and block do not agree on UC size!") }
        }

        let mut filters: Vec<Filter> = Vec::new();
        for _ in 0..filter_count { filters.push(parse_filters(input)?) }

        // Padding. Same spec deviation as last time.
        let padding = (start + actual_size)
           .checked_sub(input.cursor + 4)
           .ok_or_else(|| anyhow!("Invalid padding size!"))?;

        input.advance(padding)?;

        let crc_bytes: &[u8; 4] = input.get(4)?.try_into()?;
        let crc32_file = u32::from_le_bytes(*crc_bytes);
        let checksum_data = &input.data()[start..input.cursor - 4];
        if crc32(checksum_data) != crc32_file { bail!("Cannot verify block checksum!") }

        let compressed_size = block_info
            .unpadded_size
            .checked_sub(actual_size as u64)
            .and_then(|v| v.checked_sub(check_size as u64))
            .ok_or_else(|| anyhow!("Unpadded block too small for block!"))?;

        let uncompressed_size = block_info.uncompressed_size;
        let data = input.get(compressed_size as usize)?;

        // Padding. Same spec deviation
        input.cursor = input.cursor.next_multiple_of(4);
        
        let check = input.get(check_size)?;
        res.push(Block { offset, filters, compressed_size, uncompressed_size, data, check });

        offset += uncompressed_size;
    }

    Ok(res)
}

fn parse_filters<'a>(input: &mut Buffer<'a>) -> Result<Filter<'a>> {
    let id = decode_number(input)?;
    let prop_size = decode_number(input)?;
    let properties = input.get(prop_size as usize)?;

    Filter::new(id, properties)
}

/// Decode the dynamically sized integers specified in the XZ spec
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
