//! Cyclic bit rotation used by the original Point Blank UDP protocol.

/// Constants exposed by the original Plugin.Core Bitwise helper.
pub const CRYPTO: [u16; 3] = [29_890, 32_759, 1_360];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidShift(pub u8);

/// Derive the per-session rotation (valid for positive session identifiers).
pub fn session_shift(session_id: u32) -> u8 {
    (((session_id.wrapping_add(u32::from(CRYPTO[0]))) % 7) + 1) as u8
}

/// Rotate the whole byte buffer left by shift bits, wrapping across its ends.
pub fn bitwise_encrypt(data: &[u8], shift: u8) -> Result<Vec<u8>, InvalidShift> {
    if !(1..=7).contains(&shift) {
        return Err(InvalidShift(shift));
    }
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut output = data.to_vec();
    let first = output[0];

    for index in 0..output.len() - 1 {
        output[index] = (output[index + 1] >> (8 - shift))
            | (output[index] << shift);
    }

    let last = output.len() - 1;
    output[last] = (first >> (8 - shift)) | (output[last] << shift);
    Ok(output)
}

/// Inverse of bitwise_encrypt.
pub fn bitwise_decrypt(data: &[u8], shift: u8) -> Result<Vec<u8>, InvalidShift> {
    if !(1..=7).contains(&shift) {
        return Err(InvalidShift(shift));
    }
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut output = data.to_vec();
    let last = output[output.len() - 1];

    for index in (1..output.len()).rev() {
        output[index] = (output[index - 1] << (8 - shift))
            | (output[index] >> shift);
    }

    output[0] = (last << (8 - shift)) | (output[0] >> shift);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_buffers_and_invalid_shifts_are_handled() {
        assert_eq!(bitwise_encrypt(&[], 3), Ok(Vec::new()));
        assert_eq!(bitwise_decrypt(&[], 3), Ok(Vec::new()));
        assert_eq!(bitwise_encrypt(&[1, 2], 0), Err(InvalidShift(0)));
        assert_eq!(bitwise_decrypt(&[1, 2], 8), Err(InvalidShift(8)));
    }
}
