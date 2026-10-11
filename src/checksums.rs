const CRC32_POLYNOMIAL: u32 = 0xEDB88320;
const CRC64_POLYNOMIAL: u64 = 0xC96C5795D7870F42;
const SHA256_BLOCK_SIZE: usize = 64;
const SHA256_LENGTH_FIELD_SIZE: usize = 8;
const SHA256_DIGEST_SIZE: usize = 32;

const CRC32_TABLE: [u32; 256] = {
    let mut table = [0; 256];

    let mut i = 0;
    while i < 256 {
        let mut c = i;
        let mut k = 0;

        while k < 8 {
            if (c & 1) == 1 { c = (c >> 1) ^ CRC32_POLYNOMIAL }
            else { c >>= 1 }

            k += 1;
        }

        table[i as usize] = c;
        i += 1;
    }

    table
};

const CRC64_TABLE: [u64; 256] = {
    let mut table = [0; 256];

    let mut i = 0;
    while i < 256 {
        let mut c = i;
        let mut k = 0;

        while k < 8 {
            if (c & 1) == 1 { c = ( c >> 1) ^ CRC64_POLYNOMIAL }
            else { c >>= 1 }

            k += 1;
        }

        table[i as usize] = c;
        i += 1;
    }

    table
};

const SHA256_INITIAL_STATE: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
];

pub fn crc32(data: &[u8]) -> u32 {
    let mut res = u32::MAX;

    for &b in data {
        let idx = (res ^ b as u32) as usize & 0xFF;
        res = (CRC32_TABLE[idx]) ^ (res >> 8)
    }

    !res
}

pub fn crc64(data: &[u8]) -> u64 {
    let mut res = u64::MAX;

    for &b in data {
        let idx = ((res ^ b as u64) & 0xFF) as usize;
        res = CRC64_TABLE[idx] ^ (res >> 8);
    }

    !res
}

pub fn sha256(data: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    let full_blocks = data.chunks_exact(SHA256_BLOCK_SIZE);
    let rem = full_blocks.remainder();

    let mut tail = [0; SHA256_BLOCK_SIZE * 2];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;

    let tail_len = if rem.len() < SHA256_BLOCK_SIZE - SHA256_LENGTH_FIELD_SIZE { SHA256_BLOCK_SIZE }
    else { SHA256_BLOCK_SIZE * 2 };

    let bit_length = (data.len() as u64).wrapping_mul(8);
    tail[tail_len - SHA256_LENGTH_FIELD_SIZE..tail_len].copy_from_slice(&bit_length.to_be_bytes());

    let mut state = SHA256_INITIAL_STATE;
    for block in full_blocks.chain(tail[..tail_len].chunks_exact(SHA256_BLOCK_SIZE)) {
        sha256_compress(&mut state, block);
    }

    let mut digest = [0; SHA256_DIGEST_SIZE];

    for (digest_chunk, state_word) in digest.chunks_exact_mut(4).zip(state) {
        digest_chunk.copy_from_slice(&state_word.to_be_bytes());
    }

    digest
}

fn sha256_compress(state: &mut [u32; 8], block: &[u8]) {
    let mut msg_schedule = [0; 64];

    for (word_index, word) in msg_schedule.iter_mut().enumerate().take(16) {
        let start = word_index * 4;

        // Unwrap: we are reading a 4 byte slice, which can defenitely be parsed into a &[u8; 4]. Safe
        *word = u32::from_be_bytes(block[start..start + 4].try_into().unwrap());
    }

    for word_index in 16..64 {
        let older = msg_schedule[word_index - 15];
        let recent = msg_schedule[word_index - 2];

        let sched_sigma0 = older.rotate_right(7) ^ older.rotate_right(18) ^ (older >> 3);
        let sched_sigma1 = recent.rotate_right(17) ^ recent.rotate_right(19) ^ (recent >> 10);

        msg_schedule[word_index] = msg_schedule[word_index - 16]
            .wrapping_add(sched_sigma0)
            .wrapping_add(sched_sigma1)
            .wrapping_add(msg_schedule[word_index - 7]);
    }

    // Compression
    let [mut work_a, mut work_b, mut work_c, mut work_d,
        mut work_e, mut work_f, mut work_g, mut work_h] = *state;

    for round in 0..64 {
        let big_sigma1 = work_e.rotate_right(6) ^ work_e.rotate_right(11) ^ work_e.rotate_right(25);
        let choice = (work_e & work_f) ^ (!work_e & work_g);
        let temp1 = work_h
            .wrapping_add(big_sigma1)
            .wrapping_add(choice)
            .wrapping_add(SHA256_ROUND_CONSTANTS[round])
            .wrapping_add(msg_schedule[round]);

        let big_sigma0 = work_a.rotate_right(2) ^ work_a.rotate_right(13) ^ work_a.rotate_right(22);
        let majority = (work_a & work_b) ^ (work_a & work_c) ^ (work_b & work_c);
        let temp2 = big_sigma0.wrapping_add(majority);

        work_h = work_g;
        work_g = work_f;
        work_f = work_e;
        work_e = work_d.wrapping_add(temp1);
        work_d = work_c;
        work_c = work_b;
        work_b = work_a;
        work_a = temp1.wrapping_add(temp2);
    }

    let working_values = [work_a, work_b, work_c, work_d, work_e, work_f, work_g, work_h];
    for (state_word, working_value) in state.iter_mut().zip(working_values) {
        *state_word = state_word.wrapping_add(working_value);
    }

}


#[cfg(test)]
mod tests {
    use crate::checksums::{SHA256_DIGEST_SIZE, crc32, crc64, sha256};

    #[test]
    fn test_crc32() {
        assert_eq!(crc32(b"Hello, World!"), 0xEC4AC3D0);
        assert_eq!(crc32(b"Sample String"), 0xA0FB9032);
        assert_ne!(crc32(b"Hello, World!"), 0x0);
    }

    #[test]
    fn test_crc64() {
        assert_eq!(crc64(b"Hello, World!"), 0x280633F05C647B2C);
        assert_eq!(crc64(b"Sample String"), 0xE64853BE08EAF92A);
        assert_ne!(crc64(b"Hello, World!"), 0x0);
    }

    #[test]
    fn test_sha256() {
        assert_eq!(
            sha256(b"Hello, World!"),
            [
                0xDF, 0xFD, 0x60, 0x21, 0xBB, 0x2B, 0xD5, 0xB0,
                0xAF, 0x67, 0x62, 0x90, 0x80, 0x9E, 0xC3, 0xA5,
                0x31, 0x91, 0xDD, 0x81, 0xC7, 0xF7, 0x0A, 0x4B,
                0x28, 0x68, 0x8A, 0x36, 0x21, 0x82, 0x98, 0x6F,
            ]
        );
        assert_eq!(
            sha256(b"Sample String"),
            [
                0x87, 0x20, 0x7A, 0xA0, 0xFF, 0xD6, 0x9F, 0xC6,
                0x20, 0x3C, 0x68, 0xB9, 0x8C, 0x09, 0xE5, 0x52,
                0xA4, 0xD7, 0xBE, 0x46, 0xE1, 0xA4, 0xC9, 0xB7,
                0x23, 0xF0, 0x6C, 0x3A, 0xFC, 0x52, 0x81, 0x0F,
            ]
        );
        assert_ne!(sha256(b"Hello, World!"), [0u8; SHA256_DIGEST_SIZE]);
    }
}