//! Stream framing for Point Blank client/server packets.

pub const ENCRYPTED_FLAG: u16 = 0x8000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameTooLarge(pub usize);

/// Build the client-to-server encrypted frame:
/// [u16 length | 0x8000][CMess bytes][one zero trailer byte].
pub fn build_encrypted_frame(cmess: &[u8]) -> Result<Vec<u8>, FrameTooLarge> {
    if cmess.len() > 0x7fff {
        return Err(FrameTooLarge(cmess.len()));
    }

    let header = (cmess.len() as u16) | ENCRYPTED_FLAG;
    let mut frame = vec![0; 3 + cmess.len()];
    frame[..2].copy_from_slice(&header.to_le_bytes());
    frame[2..2 + cmess.len()].copy_from_slice(cmess);
    Ok(frame)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub payload: Vec<u8>,
    pub encrypted: bool,
}

/// Build a plaintext server-to-client frame: [u16 (payload_len + 2)][payload][five zero bytes].
pub fn build_plain_server_frame(payload: &[u8]) -> Result<Vec<u8>, FrameTooLarge> {
    let declared_len = payload.len().checked_add(2).ok_or(FrameTooLarge(payload.len()))?;
    if declared_len > u16::MAX as usize { return Err(FrameTooLarge(payload.len())); }
    let mut frame = Vec::with_capacity(payload.len() + 7);
    frame.extend_from_slice(&(declared_len as u16).to_le_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&[0; 5]);
    Ok(frame)
}

/// Incremental decoder for the server-to-client TCP byte stream.
///
/// Plain frames occupy 5 + payload_len wire bytes; encrypted frames occupy
/// 3 + payload_len. The plain server header declares N + 2, so the first two
/// of the five zero trailer bytes are included in the emitted payload.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    pending: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn push(&mut self, chunk: &[u8]) -> Vec<Frame> {
        self.pending.extend_from_slice(chunk);
        let mut frames = Vec::new();
        let mut offset = 0;

        while self.pending.len().saturating_sub(offset) >= 2 {
            let header = u16::from_le_bytes([self.pending[offset], self.pending[offset + 1]]);
            let encrypted = (header & ENCRYPTED_FLAG) != 0;
            let payload_len = usize::from(header & !ENCRYPTED_FLAG);
            let wire_len = if encrypted {
                3 + payload_len
            } else {
                5 + payload_len
            };

            if wire_len > self.pending.len() - offset {
                break;
            }

            if payload_len >= 2 {
                let start = offset + 2;
                let end = start + payload_len;
                frames.push(Frame {
                    payload: self.pending[start..end].to_vec(),
                    encrypted,
                });
            }

            offset += wire_len;
        }

        if offset > 0 {
            self.pending.drain(..offset);
        }

        frames
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_frame(payload: &[u8]) -> Vec<u8> {
        let length = (payload.len() + 2) as u16;
        let mut frame = Vec::with_capacity(payload.len() + 7);
        frame.extend_from_slice(&length.to_le_bytes());
        frame.extend_from_slice(payload);
        frame.extend_from_slice(&[0; 5]);
        frame
    }

    #[test]
    fn decoder_reassembles_frames_split_across_chunks() {
        let mut stream = server_frame(&[0x02, 0x09, 1, 2, 3]);
        stream.extend_from_slice(&server_frame(&[0x1d, 0x09]));

        let mut decoder = FrameDecoder::new();
        let first = decoder.push(&stream[..4]);
        let second = decoder.push(&stream[4..13]);
        let third = decoder.push(&stream[13..]);
        let frames = [first, second, third].concat();

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].payload.len(), 7);
        assert_eq!(&frames[0].payload[..5], &[0x02, 0x09, 1, 2, 3]);
        assert_eq!(&frames[0].payload[5..], &[0, 0]);
        assert!(!frames[0].encrypted);
        assert_eq!(frames[1].payload.len(), 4);
        assert_eq!(&frames[1].payload[..2], &[0x1d, 0x09]);
        assert_eq!(&frames[1].payload[2..], &[0, 0]);
        assert_eq!(decoder.pending_len(), 0);
    }

    #[test]
    fn encrypted_frame_has_flag_and_trailer() {
        let frame = build_encrypted_frame(&[0xaa; 10]).unwrap();
        assert_eq!(frame.len(), 13);
        assert_eq!(
            u16::from_le_bytes([frame[0], frame[1]]),
            ENCRYPTED_FLAG | 10
        );
        assert_eq!(frame[12], 0);
    }

    #[test]
    fn frame_builder_rejects_payloads_that_do_not_fit_the_header() {
        assert_eq!(
            build_encrypted_frame(&vec![0; 0x8000]),
            Err(FrameTooLarge(0x8000))
        );
    }
}
