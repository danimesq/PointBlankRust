//! Point Blank Auth connection protocol.
//!
//! This crate owns the Auth-side session handshake, CMess ingress, seed-window
//! validation, packet admission and opcode classification. Account/database
//! policy and Game state belong to higher service layers.

mod keys;
mod session;

pub use keys::{generate_session_keys, generate_session_seed, SessionKeys, AUTH_RSA_BITS, AUTH_SECURITY_KEY};
pub use session::{
    AuthConfig, AuthError, AuthOpcode, AuthPacket, AuthSession, AuthSessionState,
    DEFAULT_FIRST_PACKET_OPCODES, MAX_FRAMES_PER_CHUNK,
};
