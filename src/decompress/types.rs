use anyhow::{Result, bail};

#[derive(Debug)]
pub struct XZInfo<'a> {
    pub checksum_alg: Checksum,
    pub blocks: Vec<Block<'a>>
}

#[derive(Debug)]
pub enum Checksum {
    Sha256,
    Crc32,
    Crc64,
    None
}

impl Checksum {
    pub fn size(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Crc32 => 4,
            Self::Crc64 => 8,
            Self::Sha256 => 32
        }
    }
}

impl Checksum {
    pub fn from_stream_flags(flags: u8) -> Result<Self> {
        if flags & 0xF0 != 0 { bail!("Invalid stream flags!") }

        match flags {
            0x0 => Ok(Self::None),
            0x1 => Ok(Self::Crc32),
            0x4 => Ok(Self::Crc64),
            0xA => Ok(Self::Sha256),
            _ => bail!("Invalid stream flags!")
        }
    }
}

#[derive(Debug)]
pub struct IndexRecord {
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
