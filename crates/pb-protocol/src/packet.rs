//! Little-endian packet reader/writer matching the reference client's
//! BinaryReader/BinaryWriter-compatible helpers.

use std::error::Error;
use std::fmt;

/// A packet did not contain enough bytes for the requested field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    UnexpectedEnd {
        offset: usize,
        needed: usize,
        remaining: usize,
    },
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd {
                offset,
                needed,
                remaining,
            } => write!(
                f,
                "packet ended at byte {offset}: need {needed} bytes, have {remaining}"
            ),
        }
    }
}

impl Error for PacketError {}

/// Bounds-checked reader for Point Blank packet bodies.
pub struct PacketReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> PacketReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    pub fn with_offset(data: &'a [u8], offset: usize) -> Result<Self, PacketError> {
        if offset > data.len() {
            return Err(PacketError::UnexpectedEnd {
                offset: data.len(),
                needed: offset - data.len(),
                remaining: 0,
            });
        }
        Ok(Self {
            data,
            position: offset,
        })
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.position
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], PacketError> {
        let end = self.position.checked_add(count).ok_or(PacketError::UnexpectedEnd {
            offset: self.position,
            needed: count,
            remaining: self.remaining(),
        })?;

        if end > self.data.len() {
            return Err(PacketError::UnexpectedEnd {
                offset: self.position,
                needed: count,
                remaining: self.remaining(),
            });
        }

        let start = self.position;
        self.position = end;
        Ok(&self.data[start..end])
    }

    /// Read an unsigned 8-bit field.
    pub fn read_c(&mut self) -> Result<u8, PacketError> {
        Ok(self.take(1)?[0])
    }

    /// Read an unsigned 16-bit little-endian field.
    pub fn read_h(&mut self) -> Result<u16, PacketError> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("length checked"),
        ))
    }

    /// Read an unsigned 32-bit little-endian field.
    pub fn read_d(&mut self) -> Result<u32, PacketError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("length checked"),
        ))
    }

    /// Read a signed 32-bit little-endian field.
    pub fn read_signed_d(&mut self) -> Result<i32, PacketError> {
        Ok(i32::from_le_bytes(
            self.take(4)?.try_into().expect("length checked"),
        ))
    }

    /// Read a signed 64-bit little-endian field.
    pub fn read_q(&mut self) -> Result<i64, PacketError> {
        Ok(i64::from_le_bytes(
            self.take(8)?.try_into().expect("length checked"),
        ))
    }

    /// Read an IEEE-754 little-endian 32-bit float.
    pub fn read_t(&mut self) -> Result<f32, PacketError> {
        Ok(f32::from_le_bytes(
            self.take(4)?.try_into().expect("length checked"),
        ))
    }

    /// Read and copy an arbitrary byte range.
    pub fn read_b(&mut self, count: usize) -> Result<Vec<u8>, PacketError> {
        Ok(self.take(count)?.to_vec())
    }

    /// Advance by a byte count without decoding the skipped bytes.
    pub fn skip(&mut self, count: usize) -> Result<(), PacketError> {
        self.take(count)?;
        Ok(())
    }

    /// Read a fixed-width UTF-8 field, stopping at its first NUL byte.
    /// Invalid UTF-8 is replaced, matching the reference TextDecoder behavior.
    pub fn read_s(&mut self, count: usize) -> Result<String, PacketError> {
        let bytes = self.take(count)?;
        let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
        Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }

    /// Read a fixed-width UTF-16LE field, stopping at its first NUL code unit.
    /// A trailing odd byte and invalid surrogate sequences are replaced.
    pub fn read_u(&mut self, count: usize) -> Result<String, PacketError> {
        let bytes = self.take(count)?;
        let mut units = Vec::with_capacity((count + 1) / 2);
        let mut terminated = false;

        for pair in bytes.chunks_exact(2) {
            let unit = u16::from_le_bytes([pair[0], pair[1]]);
            if unit == 0 {
                terminated = true;
                break;
            }
            units.push(unit);
        }

        if bytes.len() % 2 != 0 && !terminated {
            units.push(0xfffd);
        }

        Ok(String::from_utf16_lossy(&units))
    }
}

/// Growable packet writer. All multi-byte fields are written little-endian.
#[derive(Debug, Clone, Default)]
pub struct PacketWriter {
    bytes: Vec<u8>,
}

impl PacketWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn write_c(&mut self, value: u8) -> &mut Self {
        self.bytes.push(value);
        self
    }

    pub fn write_h(&mut self, value: u16) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn write_d(&mut self, value: u32) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn write_signed_d(&mut self, value: i32) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn write_q(&mut self, value: i64) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn write_t(&mut self, value: f32) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn write_b(&mut self, value: &[u8]) -> &mut Self {
        self.bytes.extend_from_slice(value);
        self
    }

    pub fn zeros(&mut self, count: usize) -> &mut Self {
        self.bytes.resize(self.bytes.len().saturating_add(count), 0);
        self
    }

    /// Write UTF-8 bytes, truncated to count bytes and then NUL-padded.
    pub fn write_s(&mut self, value: &str, count: usize) -> &mut Self {
        let bytes = value.as_bytes();
        let copied = bytes.len().min(count);
        self.write_b(&bytes[..copied]);
        self.zeros(count - copied);
        self
    }

    /// Write only complete UTF-16LE code units, then NUL-pad to count bytes.
    /// This mirrors the reference writer, which never splits a code unit even
    /// when the fixed-width field has an odd byte count.
    pub fn write_u(&mut self, value: &str, count: usize) -> &mut Self {
        let mut bytes = Vec::with_capacity(count);
        for unit in value.encode_utf16() {
            if bytes.len().saturating_add(2) > count {
                break;
            }
            bytes.extend_from_slice(&unit.to_le_bytes());
        }

        let copied = bytes.len();
        self.write_b(&bytes);
        self.zeros(count - copied);
        self
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_fields_round_trip_little_endian() {
        let mut writer = PacketWriter::with_capacity(1);
        writer
            .write_c(0x12)
            .write_h(0x3456)
            .write_d(0x789a_bcde)
            .write_signed_d(-2)
            .write_q(-3)
            .write_t(1.5);

        assert_eq!(
            &writer.as_slice()[..7],
            &[0x12, 0x56, 0x34, 0xde, 0xbc, 0x9a, 0x78]
        );

        let bytes = writer.into_bytes();
        let mut reader = PacketReader::new(&bytes);
        assert_eq!(reader.read_c(), Ok(0x12));
        assert_eq!(reader.read_h(), Ok(0x3456));
        assert_eq!(reader.read_d(), Ok(0x789a_bcde));
        assert_eq!(reader.read_signed_d(), Ok(-2));
        assert_eq!(reader.read_q(), Ok(-3));
        assert_eq!(reader.read_t(), Ok(1.5));
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn fixed_width_strings_match_byte_counts() {
        let mut writer = PacketWriter::new();
        writer.write_s("áB", 4).write_u("A🧡", 6);
        let bytes = writer.into_bytes();

        let mut reader = PacketReader::new(&bytes);
        assert_eq!(reader.read_s(4), Ok("áB".to_owned()));
        assert_eq!(reader.read_u(6), Ok("A🧡".to_owned()));
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn utf16_writer_never_splits_a_code_unit() {
        let mut writer = PacketWriter::new();
        writer.write_u("AB", 3);
        assert_eq!(writer.as_slice(), &[0x41, 0x00, 0x00]);
    }

    #[test]
    fn reader_rejects_truncated_fields() {
        let mut reader = PacketReader::new(&[0x01, 0x02, 0x03]);
        assert_eq!(reader.read_h(), Ok(0x0201));
        assert!(matches!(
            reader.read_d(),
            Err(PacketError::UnexpectedEnd {
                offset: 2,
                needed: 4,
                remaining: 1
            })
        ));
    }
}
