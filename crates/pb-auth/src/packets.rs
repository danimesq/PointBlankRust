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

/// Auth protocol error codes returned by LOGIN_ACK and disconnect packets.
pub mod error_code {
    pub const SUCCESS: u32 = 0x0000_0000;
    pub const FAIL: u32 = 0x8000_0000;
    pub const LOGIN_ALREADY_LOGIN: u32 = 0x8000_0101;
    pub const LOGIN_TIME_OUT_2: u32 = 0x8000_0106;
    pub const LOGIN_BLOCK_ACCOUNT: u32 = 0x8000_0107;
    pub const LOGIN_ID_PASS_INCORRECT: u32 = 0x8000_0117;
    pub const LOGIN_BLOCK_IP: u32 = 0x8000_0121;
    pub const DISCONNECT_INVALID_LOGIN: u32 = 0x8000_0100;
}

/// Minimal account identity required by LOGIN_ACK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginIdentity {
    pub player_id: u64,
    pub username: String,
}

/// Reproduce AllUtils.ValidateKey: {hw%999:000}{pid%999:000}{session%999:000}.
pub fn validate_key(player_id: u64, session_id: u32, hw_spec0: u32) -> u32 {
    let value = format!(
        "{:03}{:03}{:03}",
        hw_spec0 % 999,
        player_id % 999,
        session_id % 999
    );
    value.parse::<u32>().unwrap_or(0)
}

/// C# BaseServerPacket.WriteS: append all UTF-8 bytes, then pad by UTF-16 code-unit count.
fn write_compat_string(writer: &mut PacketWriter, value: &str, count: usize) {
    writer.write_b(value.as_bytes());
    writer.zeros(count.saturating_sub(value.encode_utf16().count()));
}

/// PROTOCOL_BASE_LOGIN_ACK (1283).
pub fn login_ack(
    error: u32,
    verification_key: u32,
    features: u32,
    account: Option<&LoginIdentity>,
) -> Vec<u8> {
    let mut writer = PacketWriter::new();
    writer
        .write_h(1283)
        .write_h(0)
        .write_d(verification_key)
        .write_b(&[0x01, 0x03, 0x00])
        .zeros(9)
        .write_d(features)
        .write_h(1531)
        .zeros(16);

    if error == error_code::SUCCESS {
        if let Some(account) = account {
            let player_id = account.player_id.to_string();
            let player_id_len = player_id.encode_utf16().count();
            let username_len = account.username.encode_utf16().count();
            writer.write_c(player_id_len as u8);
            write_compat_string(&mut writer, &player_id, player_id_len);
            writer.write_c(0).write_c(username_len as u8);
            write_compat_string(&mut writer, &account.username, username_len);
            writer.write_b(&account.player_id.to_le_bytes());
        } else {
            writer.zeros(11);
        }
    } else {
        writer.zeros(11);
    }

    writer.write_d(error);
    writer.into_bytes()
}

/// PROTOCOL_AUTH_GET_POINT_CASH_ACK (1061).
pub fn point_cash_ack(error: u32, cash: u32, gold: u32, tags: u32) -> Vec<u8> {
    let mut writer = PacketWriter::with_capacity(18);
    writer
        .write_h(1061)
        .write_d(error)
        .write_d(cash)
        .write_d(gold)
        .write_d(tags);
    writer.into_bytes()
}

/// PROTOCOL_BASE_USER_LEAVE_ACK (2329).
pub fn user_leave_ack(error: u32) -> Vec<u8> {
    let mut writer = PacketWriter::with_capacity(8);
    writer.write_h(2329).write_d(error).write_h(0);
    writer.into_bytes()
}

/// PROTOCOL_SERVER_MESSAGE_DISCONNECTIONSUCCESS_ACK (3074).
pub fn disconnection_success_ack(error: u32) -> Vec<u8> {
    let mut writer = PacketWriter::with_capacity(6);
    writer.write_h(3074).write_d(error);
    writer.into_bytes()
}

/// PROTOCOL_AUTH_ACCOUNT_KICK_ACK (2009). The C# constructor argument is not serialized.
pub fn account_kick_ack() -> Vec<u8> {
    let mut writer = PacketWriter::with_capacity(22);
    writer.write_h(2009).zeros(19).write_c(0);
    writer.into_bytes()
}

/// PROTOCOL_SERVER_MESSAGE_ERROR_ACK (3078).
pub fn server_message_error_ack(error: u32) -> Vec<u8> {
    let mut writer = PacketWriter::with_capacity(6);
    writer.write_h(3078).write_d(error);
    writer.into_bytes()
}

#[cfg(test)]
mod reply_tests {
    use super::*;

    #[test]
    fn validate_key_matches_reference_vectors() {
        assert_eq!(validate_key(126, 1, 0x02424557), 494_126_001);
        assert_eq!(validate_key(1000, 999, 5), 5_001_000);
    }

    #[test]
    fn login_ack_success_and_failure_layouts_match_reference() {
        let account = LoginIdentity {
            player_id: 126,
            username: "w17abc".to_owned(),
        };
        let ok = login_ack(0, 123_456_789, 0x87fd_776e, Some(&account));
        assert_eq!(
            ok.len(),
            2 + 2 + 4 + 12 + 4 + 2 + 16 + 1 + 3 + 1 + 1 + 6 + 8 + 4
        );
        assert_eq!(
            u32::from_le_bytes(ok[4..8].try_into().unwrap()),
            123_456_789
        );
        assert_eq!(
            u32::from_le_bytes(ok[20..24].try_into().unwrap()),
            0x87fd_776e
        );
        assert_eq!(u16::from_le_bytes(ok[24..26].try_into().unwrap()), 1531);
        assert_eq!(&ok[43..46], b"126");
        assert_eq!(u64::from_le_bytes(ok[54..62].try_into().unwrap()), 126);

        let bad = login_ack(error_code::LOGIN_ID_PASS_INCORRECT, 0, 1, None);
        assert_eq!(bad.len(), 2 + 2 + 4 + 12 + 4 + 2 + 16 + 11 + 4);
        assert_eq!(
            u32::from_le_bytes(bad[bad.len() - 4..].try_into().unwrap()),
            0x8000_0117
        );
    }

    #[test]
    fn auth_reply_packet_opcodes_and_lengths_match_reference() {
        assert_eq!(point_cash_ack(0, 1, 2, 3).len(), 18);
        assert_eq!(user_leave_ack(0), [0x19, 0x09, 0, 0, 0, 0, 0, 0]);
        assert_eq!(disconnection_success_ack(0).len(), 6);
        assert_eq!(account_kick_ack().len(), 22);
        assert_eq!(server_message_error_ack(0).len(), 6);
    }
}
