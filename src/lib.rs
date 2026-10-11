mod decompress;

use anyhow::{Result, anyhow, bail};
pub use decompress::decompress;

const XZ_MAGIC: [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
const FOOTER_MAGIC: [u8; 2] = [0x59, 0x5A];

pub struct Buffer<'a> {
    data: &'a [u8],
    cursor: usize
}

impl<'a> Buffer<'a> {
    /// Create a new `Buffer`
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            cursor: 0
        }
    }

    /// Get `n` bytes from current position and advances the cursor
    pub fn get(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.data.len() - self.cursor { bail!("Unexpected EOF!") }

        let data = &self.data[self.cursor..self.cursor + n];
        self.cursor += n;
        
        Ok(data)
    }

    /// Get the next value
    pub fn next_val(&mut self) -> Result<u8> {
        if self.cursor + 1 > self.data.len() { bail!("Unexpected EOF!") }
        
        let data = self.data[self.cursor];
        self.cursor += 1;

        Ok(data)
    }

    /// Peek at a value at the absolute index `i`
    pub fn peek(&self, i: usize) -> Result<u8> {
        if i >= self.data.len() { bail!("Unexpected EOF!") }
        else { Ok(self.data[i]) }
    }

    /// Get a reference to the underlying data
    pub fn data(&self) -> &[u8] { self.data }

    /// Get the current index into the buffer
    pub fn position(&self) -> usize { self.cursor }

    /// Create a new `Buffer` starting at `n` into this buffer's data
    pub fn child(&self, n: usize) -> Result<Self> {
        if n > self.data.len() { bail!("Buffer too small!") }
        
        Ok(Self { data: &self.data[n..], cursor: 0 })
    }

    /// Advance the cursor by `n`
    pub fn advance(&mut self, n: usize) -> Result<()> {
        if n > self.data.len() - self.cursor { bail!("Buffer too small!") }
        self.cursor += n;

        Ok(())
    }
}

pub struct BackwardsBuffer<'a> {
    data: &'a [u8],
    cursor: usize
}

impl<'a> BackwardsBuffer<'a> {
    /// Create a new `BackwardsBuffer`
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            cursor: data.len()
        }
    }

    /// Get `n` bytes from current position and decrements the cursor
    pub fn get(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.cursor < n { bail!("Unexpected EOF!") }

        let data = &self.data[self.cursor - n..self.cursor];
        self.cursor -= n;
        
        Ok(data)
    }

    /// Get the next value
    pub fn next_val(&mut self) -> Result<u8> {
        self.cursor = self.cursor.checked_sub(1).ok_or_else(|| anyhow!("Unexpected EOF!"))?;        
        let data = self.data[self.cursor];

        Ok(data)
    }

    /// Peek at a value at the absolute index `i`
    pub fn peek(&self, i: usize) -> Result<u8> {
        if i >= self.data.len() { bail!("Unexpected EOF!") }
        else { Ok(self.data[i]) }
    }

    /// Get a reference to the underlying data
    pub fn data(&self) -> &[u8] { self.data }

    /// Get the current index into the buffer
    pub fn position(&self) -> usize { self.cursor }
}
