use anyhow::{Result, bail};
use lzma_turbo::Lzma2Decoder;

use super::types::Filter;

pub fn decode_filter(encoded_data: &[u8], filter: Filter, uncompressed_size: usize) -> Result<Vec<u8>> {
    use super::types::FilterType::*;
    match filter.filter_type {
        LZMA2 => decode_lzma2_filter(encoded_data, filter.properties[0], uncompressed_size),
        Delta => decode_delta_filter(encoded_data, filter.properties[0]),
        _ => bail!("Unsupported format!")
    }
}

fn decode_lzma2_filter(encoded_data: &[u8], properties: u8, uncompressed_size: usize) -> Result<Vec<u8>> {
    let mut decoder = Lzma2Decoder::new(properties)?;
    let mut out = vec![0; uncompressed_size];

    let p = decoder.decode(encoded_data, &mut out, lzma_turbo::FinishMode::End)?;
    if p.written != uncompressed_size { bail!("LZMA2 wrote {} of {uncompressed_size} bytes", p.written); }

    Ok(out)
}

fn decode_delta_filter(encoded_data: &[u8], props_byte: u8) -> Result<Vec<u8>> {
    let distance = props_byte as usize + 1;
    let mut output = encoded_data.to_vec();

    let mut start = distance;
    while start < output.len() {
        let end = (start + distance).min(output.len());
        let (low, high) = output.split_at_mut(start);
        let prev = &low[start - distance..end - distance];
        for (x, &p) in high[..end - start].iter_mut().zip(prev) {
            *x = x.wrapping_add(p);
        }
        start = end;
    }

    Ok(output)
}