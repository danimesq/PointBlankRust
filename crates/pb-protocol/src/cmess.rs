//! CMess TCP cipher and the Point Blank session-seed LCG.
//!
//! The algorithms reproduce the byte layout used by the reference port.
//! Encryption randomness is injected by the caller so deployments can supply
//! their platform CSPRNG without making the protocol crate pick a runtime.

use std::error::Error;
use std::fmt;

pub const MODE_AUTH: u8 = 1;
pub const MODE_GAME: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmessRandom {
    pub r0: u8,
    pub r1: u8,
    pub r2: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmessError {
    InvalidKeyLength(usize),
    InvalidCiphertext,
    InvalidPadding,
}

impl fmt::Display for CmessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(length) => {
                write!(f, "CMess key must be 16 bytes, got {length}")
            }
            Self::InvalidCiphertext => f.write_str("invalid CMess ciphertext"),
            Self::InvalidPadding => f.write_str("invalid CMess padding"),
        }
    }
}

impl Error for CmessError {}

fn bits_at(register: &[u8], bit_position: usize) -> u8 {
    let byte_index = (bit_position >> 3) & 7;
    let bit_offset = bit_position & 7;

    if bit_offset == 0 {
        register[byte_index]
    } else {
        let low = (register[byte_index] & (0xff >> bit_offset)) << bit_offset;
        let high = register[(byte_index + 1) & 7] >> (8 - bit_offset);
        low | high
    }
}

fn update_state(k0: &mut [u8; 8], k1: &mut [u8; 8], cipher_byte: u8) {
    k0[0] ^= cipher_byte;
    k0[2] ^= cipher_byte;
    k0[4] ^= cipher_byte;
    k0[6] ^= cipher_byte;

    k1[1] ^= cipher_byte;
    k1[3] ^= cipher_byte;
    k1[5] ^= cipher_byte;
    k1[7] ^= cipher_byte;
}

fn derive_initial_state(r0: u8, r1: u8, r2: u8, mode: u8) -> (usize, usize, usize) {
    match mode {
        MODE_AUTH => (
            usize::from(r2 >> 4) + usize::from(r0),
            usize::from(r2 & 0x0f) + usize::from(r1),
            8,
        ),
        MODE_GAME => (
            usize::from(r2 & 0x0f) + usize::from(r0),
            usize::from(r2 >> 4) + usize::from(r1),
            14,
        ),
        _ => (
            usize::from(r2) + usize::from(r0),
            usize::from(r2) + usize::from(r1),
            12,
        ),
    }
}

struct Keystream {
    k0: [u8; 8],
    k1: [u8; 8],
    position: usize,
    run_xor: u8,
    p0: usize,
    p1: usize,
    step: usize,
}

impl Keystream {
    fn new(key: &[u8], random: CmessRandom, mode: u8) -> Result<Self, CmessError> {
        if key.len() < 16 {
            return Err(CmessError::InvalidKeyLength(key.len()));
        }

        let mut k0 = [0; 8];
        let mut k1 = [0; 8];
        k0.copy_from_slice(&key[..8]);
        k1.copy_from_slice(&key[8..16]);

        let (p0, p1, step) = derive_initial_state(random.r0, random.r1, random.r2, mode);

        Ok(Self {
            k0,
            k1,
            position: 0,
            run_xor: 0,
            p0,
            p1,
            step,
        })
    }

    fn next(&mut self) -> u8 {
        let s0 = bits_at(&self.k0, self.position + self.p0);
        let s1 = bits_at(&self.k1, self.position + self.p1);
        self.run_xor ^= s0 ^ s1;
        self.position = self.position + usize::from(self.run_xor) + self.step;
        self.run_xor
    }

    fn feed(&mut self, cipher_byte: u8) {
        update_state(&mut self.k0, &mut self.k1, cipher_byte);
    }
}

/// Encrypt a packet using an explicit CMess random header.
///
/// The caller must obtain r0/r1/r2 from a cryptographically secure random
/// source. This deterministic entry point is also used by compatibility tests.
pub fn cmess_encrypt_with_random(
    key: &[u8],
    plaintext: &[u8],
    mode: u8,
    random: CmessRandom,
) -> Result<Vec<u8>, CmessError> {
    let mut stream = Keystream::new(key, random, mode)?;
    let pad_len = (2usize.wrapping_sub(plaintext.len()) & 7) + 2;

    let mut output = Vec::with_capacity(4 + plaintext.len() + pad_len);
    output.extend_from_slice(&[random.r0, random.r1, random.r2, pad_len as u8]);

    for &plain_byte in plaintext {
        let cipher_byte = stream.next() ^ plain_byte;
        output.push(cipher_byte);
        stream.feed(cipher_byte);
    }

    for _ in 0..pad_len {
        let cipher_byte = (pad_len as u8) ^ stream.next();
        output.push(cipher_byte);
        stream.feed(cipher_byte);
    }

    Ok(output)
}

/// Decrypt a CMess payload. Invalid header, key, or padding is returned as an error.
pub fn cmess_decrypt(key: &[u8], ciphertext: &[u8], mode: u8) -> Result<Vec<u8>, CmessError> {
    if ciphertext.len() < 4 {
        return Err(CmessError::InvalidCiphertext);
    }

    let pad_len = usize::from(ciphertext[3]);
    if !(2..=9).contains(&pad_len) {
        return Err(CmessError::InvalidCiphertext);
    }

    let data_len = ciphertext
        .len()
        .checked_sub(4 + pad_len)
        .ok_or(CmessError::InvalidCiphertext)?;

    let random = CmessRandom {
        r0: ciphertext[0],
        r1: ciphertext[1],
        r2: ciphertext[2],
    };
    let mut stream = Keystream::new(key, random, mode)?;
    let mut plaintext = Vec::with_capacity(data_len);
    let mut offset = 4;

    for _ in 0..data_len {
        let cipher_byte = ciphertext[offset];
        plaintext.push(stream.next() ^ cipher_byte);
        stream.feed(cipher_byte);
        offset += 1;
    }

    let pad0 = stream.next() ^ ciphertext[offset];
    stream.feed(ciphertext[offset]);
    offset += 1;
    let pad1 = stream.next() ^ ciphertext[offset];

    if pad0 != pad_len as u8 || pad1 != pad_len as u8 {
        return Err(CmessError::InvalidPadding);
    }

    Ok(plaintext)
}

/// Auth/Game session-seed LCG, including the original signed 32-bit overflow.
pub fn next_session_seed(seed: i32) -> u16 {
    let wrapped = seed.wrapping_mul(214_013).wrapping_add(2_531_011);
    ((wrapped >> 16) as u32 & 0x7fff) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_rejects_short_keys_and_bad_padding() {
        assert_eq!(
            cmess_encrypt_with_random(
                &[0; 15],
                &[],
                MODE_AUTH,
                CmessRandom {
                    r0: 1,
                    r1: 2,
                    r2: 3,
                }
            ),
            Err(CmessError::InvalidKeyLength(15))
        );

        let key = [
            0x03, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xe0,
            0xf1, 0x02,
        ];
        let mut encrypted = cmess_encrypt_with_random(
            &key,
            &[0x07, 0x26, 0x45, 0x64],
            MODE_AUTH,
            CmessRandom {
                r0: 0x3b,
                r1: 0x09,
                r2: 0xc4,
            },
        )
        .unwrap();

        assert_eq!(
            cmess_decrypt(&key, &encrypted, MODE_AUTH).unwrap(),
            [0x07, 0x26, 0x45, 0x64]
        );

        encrypted[8] ^= 0x55;
        assert_eq!(
            cmess_decrypt(&key, &encrypted, MODE_AUTH),
            Err(CmessError::InvalidPadding)
        );
    }
}
