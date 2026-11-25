//! Point Blank Auth connection protocol.
//!
//! This crate owns the Auth-side session handshake, CMess ingress, seed-window
//! validation, packet admission and opcode classification. Account/database
//! policy and Game state belong to higher service layers.

mod dispatch;
mod keys;
mod login;
mod packets;
mod session;

pub use dispatch::{dispatch_auth_packet, AuthDispatchError, AuthHandlers};
pub use keys::{
    generate_session_keys, generate_session_seed, SessionKeyError, SessionKeys, AUTH_RSA_BITS,
    AUTH_SECURITY_KEY,
};
pub use login::{LoginDecodeError, LoginRequest};
pub use packets::{
    account_kick_ack, disconnection_success_ack, error_code, login_ack, point_cash_ack,
    server_message_error_ack, user_leave_ack, validate_key, AuthBootstrap, AuthBootstrapError,
    LoginIdentity,
};
pub use session::{
    AuthConfig, AuthError, AuthOpcode, AuthPacket, AuthSession, AuthSessionState,
    DEFAULT_FIRST_PACKET_OPCODES, MAX_FRAMES_PER_CHUNK,
};
