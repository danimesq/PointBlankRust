//! Auth connection bootstrap packets.

use crate::{generate_session_keys, generate_session_seed, SessionKeyError, SessionKeys};
use pb_protocol::packet::PacketWriter;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum AuthBootstrapError {
    Key(SessionKeyError),
    PacketTooLarge,
}

impl fmt::Display for AuthBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(error) => write!(f, "Auth bootstrap key error: {error}"),
            Self::PacketTooLarge => {
                f.write_str("CONNECT_ACK key material does not fit its length fields")
            }
        }
    }
}
impl Error for AuthBootstrapError {}
impl From<SessionKeyError> for AuthBootstrapError {
    fn from(value: SessionKeyError) -> Self {
        Self::Key(value)
    }
}

/// Per-connection material sent in CONNECT_ACK (2306).
#[derive(Debug, Clone)]
pub struct AuthBootstrap {
    pub session_id: u32,
    pub session_seed: u16,
    pub keys: SessionKeys,
}

impl AuthBootstrap {
    /// Generate a session seed and RSA-derived CMess keys for a new Auth session.
    pub fn generate(session_id: u32) -> Result<Self, AuthBootstrapError> {
        Ok(Self {
            session_id,
            session_seed: generate_session_seed(session_id)?,
            keys: generate_session_keys(session_id)?,
        })
    }

    /// Build the exact CONNECT_ACK payload. TCP framing is applied by the transport.
    pub fn connect_ack(&self) -> Result<Vec<u8>, AuthBootstrapError> {
        let key_blob_len = self
            .keys
            .modulus
            .len()
            .checked_add(self.keys.exponent.len())
            .and_then(|length| length.checked_add(2))
            .ok_or(AuthBootstrapError::PacketTooLarge)?;
        let key_blob_len =
            u16::try_from(key_blob_len).map_err(|_| AuthBootstrapError::PacketTooLarge)?;
        let modulus_len = u16::try_from(self.keys.modulus.len())
            .map_err(|_| AuthBootstrapError::PacketTooLarge)?;
        let session_id = self.session_id as u16;

        let mut writer = PacketWriter::with_capacity(202);
        writer
            .write_h(2306)
            .write_h(0)
            .write_c(11)
            .zeros(11)
            .write_h(key_blob_len)
            .write_h(modulus_len)
            .write_b(&self.keys.modulus)
            .write_b(&self.keys.exponent)
            .write_c(118)
            .write_h(0)
            .write_h(self.session_seed)
            .write_d(u32::from(session_id));

        Ok(writer.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_ack_matches_reference_packet_shape() {
        let bootstrap = AuthBootstrap::generate(7).unwrap();
        let packet = bootstrap.connect_ack().unwrap();
        assert_eq!(packet.len(), 202);
        assert_eq!(&packet[..5], &[0x02, 0x09, 0x00, 0x00, 0x0b]);
        assert_eq!(u16::from_le_bytes([packet[16], packet[17]]), 175);
        assert_eq!(u16::from_le_bytes([packet[18], packet[19]]), 170);
        assert_eq!(packet[193], 118);
        assert_eq!(
            u16::from_le_bytes([packet[196], packet[197]]),
            bootstrap.session_seed
        );
        assert_eq!(u32::from_le_bytes(packet[198..202].try_into().unwrap()), 7);
    }
}
