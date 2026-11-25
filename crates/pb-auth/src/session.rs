//! Stateful Auth packet admission and dispatch classification.

use pb_protocol::cmess::{cmess_decrypt, next_session_seed, CmessError, MODE_AUTH};
use pb_protocol::framing::Frame;
use std::error::Error;
use std::fmt;
use std::time::Instant;

pub const MAX_FRAMES_PER_CHUNK: usize = 32;
pub const DEFAULT_FIRST_PACKET_OPCODES: &[u16] = &[1281, 2309];

#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Maximum number of encrypted packets admitted in one burst.
    pub packet_burst: u32,
    /// Refill rate, in packets per second.
    pub packets_per_second: f64,
    /// First decrypted packet opcodes accepted by Auth.
    pub first_packet_opcodes: Vec<u16>,
    /// Maximum frames delivered from one transport read/chunk.
    pub max_frames_per_chunk: usize,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            packet_burst: 60,
            packets_per_second: 30.0,
            first_packet_opcodes: DEFAULT_FIRST_PACKET_OPCODES.to_vec(),
            max_frames_per_chunk: MAX_FRAMES_PER_CHUNK,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthSessionState {
    AwaitingFirstPacket,
    Established,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOpcode {
    Login,
    KeepAlive,
    GetPointCash,
    GetGameServerState,
    GetChannelList,
    UserLeave,
    GetUserInfo,
    GetInventoryInfo,
    GetOption,
    Unknown(u16),
}

impl AuthOpcode {
    pub fn from_raw(opcode: u16) -> Self {
        match opcode {
            1281 => Self::Login,
            2309 => Self::KeepAlive,
            1060 => Self::GetPointCash,
            1059 | 2399 => Self::GetGameServerState,
            2332 => Self::GetChannelList,
            2328 => Self::UserLeave,
            2316 => Self::GetUserInfo,
            2318 => Self::GetInventoryInfo,
            2320 => Self::GetOption,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPacket {
    pub opcode: AuthOpcode,
    pub raw_opcode: u16,
    pub seed: u16,
    /// Bytes after the 4-byte [opcode, seed] header.
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub enum AuthError {
    InvalidConfig(&'static str),
    TooManyFrames { received: usize, maximum: usize },
    PacketFlood,
    InvalidFirstPacket(u16),
    InvalidCiphertext(CmessError),
    TruncatedPacket(usize),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(f, "invalid Auth config: {message}"),
            Self::TooManyFrames { received, maximum } => {
                write!(f, "chunk contains {received} frames, maximum is {maximum}")
            }
            Self::PacketFlood => f.write_str("Auth packet rate limit exceeded"),
            Self::InvalidFirstPacket(opcode) => {
                write!(f, "invalid first Auth packet opcode {opcode}")
            }
            Self::InvalidCiphertext(error) => write!(f, "invalid Auth CMess payload: {error}"),
            Self::TruncatedPacket(length) => {
                write!(f, "decrypted Auth packet is only {length} bytes")
            }
        }
    }
}
impl Error for AuthError {}

struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_second: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: u32, refill_per_second: f64) -> Self {
        Self {
            capacity: f64::from(capacity),
            tokens: f64::from(capacity),
            refill_per_second,
            last_refill: Instant::now(),
        }
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_second).min(self.capacity);
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

/// Per-connection Auth state. It is intentionally independent of sockets and databases.
pub struct AuthSession {
    session_id: u32,
    session_seed: u16,
    next_seed: u16,
    client_key: [u8; 16],
    first_packet_id: Option<u16>,
    state: AuthSessionState,
    config: AuthConfig,
    rate: TokenBucket,
    seed_mismatches: u64,
}

impl AuthSession {
    pub fn new(
        session_id: u32,
        session_seed: u16,
        client_key: [u8; 16],
        config: AuthConfig,
    ) -> Result<Self, AuthError> {
        if config.packet_burst == 0 {
            return Err(AuthError::InvalidConfig(
                "packet_burst must be greater than zero",
            ));
        }
        if !config.packets_per_second.is_finite() || config.packets_per_second <= 0.0 {
            return Err(AuthError::InvalidConfig(
                "packets_per_second must be finite and greater than zero",
            ));
        }
        if config.max_frames_per_chunk == 0 {
            return Err(AuthError::InvalidConfig(
                "max_frames_per_chunk must be greater than zero",
            ));
        }
        if config.first_packet_opcodes.is_empty() {
            return Err(AuthError::InvalidConfig(
                "first_packet_opcodes must not be empty",
            ));
        }

        Ok(Self {
            session_id,
            session_seed,
            next_seed: session_seed,
            client_key,
            first_packet_id: None,
            state: AuthSessionState::AwaitingFirstPacket,
            rate: TokenBucket::new(config.packet_burst, config.packets_per_second),
            config,
            seed_mismatches: 0,
        })
    }

    pub fn session_id(&self) -> u32 {
        self.session_id
    }
    pub fn session_seed(&self) -> u16 {
        self.session_seed
    }
    pub fn first_packet_id(&self) -> Option<u16> {
        self.first_packet_id
    }
    pub fn state(&self) -> AuthSessionState {
        self.state
    }
    pub fn seed_mismatches(&self) -> u64 {
        self.seed_mismatches
    }

    /// Process all frames from one transport read. Plain client frames are ignored,
    /// matching the reference Auth/Game TCP session.
    pub fn process_chunk(&mut self, frames: Vec<Frame>) -> Result<Vec<AuthPacket>, AuthError> {
        if frames.len() > self.config.max_frames_per_chunk {
            self.state = AuthSessionState::Closed;
            return Err(AuthError::TooManyFrames {
                received: frames.len(),
                maximum: self.config.max_frames_per_chunk,
            });
        }
        let mut packets = Vec::new();
        for frame in frames {
            if let Some(packet) = self.process_frame(frame)? {
                packets.push(packet);
            }
        }
        Ok(packets)
    }

    pub fn process_frame(&mut self, frame: Frame) -> Result<Option<AuthPacket>, AuthError> {
        if self.state == AuthSessionState::Closed {
            return Ok(None);
        }
        if !self.rate.take() {
            self.state = AuthSessionState::Closed;
            return Err(AuthError::PacketFlood);
        }
        if !frame.encrypted {
            return Ok(None);
        }

        let plain = match cmess_decrypt(&self.client_key, &frame.payload, MODE_AUTH) {
            Ok(plain) => plain,
            Err(error) => {
                self.state = AuthSessionState::Closed;
                return Err(AuthError::InvalidCiphertext(error));
            }
        };
        if plain.len() < 4 {
            self.state = AuthSessionState::Closed;
            return Err(AuthError::TruncatedPacket(plain.len()));
        }

        let opcode = u16::from_le_bytes([plain[0], plain[1]]);
        let seed = u16::from_le_bytes([plain[2], plain[3]]);
        if self.first_packet_id.is_none() {
            if !self.config.first_packet_opcodes.contains(&opcode) {
                self.state = AuthSessionState::Closed;
                return Err(AuthError::InvalidFirstPacket(opcode));
            }
            self.first_packet_id = Some(opcode);
            self.state = AuthSessionState::Established;
        }

        if !self.check_seed(seed) {
            self.seed_mismatches = self.seed_mismatches.saturating_add(1);
            return Ok(None);
        }

        Ok(Some(AuthPacket {
            opcode: AuthOpcode::from_raw(opcode),
            raw_opcode: opcode,
            seed,
            body: plain[4..].to_vec(),
        }))
    }

    /// The reference advances the LCG and accepts a client seed found within
    /// the next sixteen generated values.
    fn check_seed(&mut self, candidate: u16) -> bool {
        for _ in 0..16 {
            self.next_seed = next_session_seed(i32::from(self.next_seed));
            if self.next_seed == candidate {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pb_protocol::cmess::{cmess_encrypt_with_random, CmessRandom};
    use pb_protocol::framing::Frame;

    fn encrypted_packet(key: &[u8; 16], opcode: u16, seed: u16) -> Frame {
        let mut plain = Vec::new();
        plain.extend_from_slice(&opcode.to_le_bytes());
        plain.extend_from_slice(&seed.to_le_bytes());
        plain.extend_from_slice(&[0xaa, 0xbb]);
        let cipher = cmess_encrypt_with_random(
            key,
            &plain,
            MODE_AUTH,
            CmessRandom {
                r0: 0x03,
                r1: 0x09,
                r2: 0xc4,
            },
        )
        .unwrap();
        Frame {
            payload: cipher,
            encrypted: true,
        }
    }

    fn session() -> AuthSession {
        AuthSession::new(7, 100, [0x42; 16], AuthConfig::default()).unwrap()
    }

    #[test]
    fn accepts_login_with_next_lcg_seed_and_dispatches_body() {
        let key = [0x42; 16];
        let mut session = session();
        let seed = next_session_seed(100);
        let packet = session
            .process_frame(encrypted_packet(&key, 1281, seed))
            .unwrap()
            .unwrap();
        assert_eq!(packet.opcode, AuthOpcode::Login);
        assert_eq!(packet.body, [0xaa, 0xbb]);
        assert_eq!(session.state(), AuthSessionState::Established);
        assert_eq!(session.first_packet_id(), Some(1281));
    }

    #[test]
    fn rejects_unexpected_first_packet() {
        let key = [0x42; 16];
        let mut session = session();
        assert!(matches!(
            session.process_frame(encrypted_packet(&key, 1060, next_session_seed(100))),
            Err(AuthError::InvalidFirstPacket(1060))
        ));
        assert_eq!(session.state(), AuthSessionState::Closed);
    }

    #[test]
    fn silently_drops_seed_outside_sixteen_step_window() {
        let key = [0x42; 16];
        let mut session = session();
        assert!(session
            .process_frame(encrypted_packet(&key, 1281, 1))
            .unwrap()
            .is_none());
        assert_eq!(session.seed_mismatches(), 1);
    }

    #[test]
    fn ignores_plaintext_client_frames() {
        let mut session = session();
        assert!(session
            .process_frame(Frame {
                payload: vec![1, 2, 3],
                encrypted: false
            })
            .unwrap()
            .is_none());
    }

    #[test]
    fn closes_after_packet_burst_is_exhausted() {
        let key = [0x42; 16];
        let mut cfg = AuthConfig::default();
        cfg.packet_burst = 1;
        let mut session = AuthSession::new(7, 100, key, cfg).unwrap();
        let seed = next_session_seed(100);
        assert!(session
            .process_frame(encrypted_packet(&key, 1281, seed))
            .unwrap()
            .is_some());
        assert!(matches!(
            session.process_frame(encrypted_packet(&key, 2309, next_session_seed(seed))),
            Err(AuthError::PacketFlood)
        ));
    }
}
