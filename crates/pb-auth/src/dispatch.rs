//! Auth opcode dispatch boundary. Persistent account logic is supplied by the server layer.

use crate::{AuthOpcode, AuthPacket};
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDispatchError {
    Handler(String),
}

impl fmt::Display for AuthDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handler(message) => write!(f, "Auth handler failed: {message}"),
        }
    }
}
impl Error for AuthDispatchError {}

/// Application-level Auth handlers. Implementations own account/database policy;
/// the protocol crate only validates and routes authenticated packet envelopes.
pub trait AuthHandlers {
    fn login(&mut self, packet: AuthPacket) -> Result<(), AuthDispatchError>;
    fn keep_alive(&mut self, packet: AuthPacket) -> Result<(), AuthDispatchError>;
    fn get_point_cash(&mut self, packet: AuthPacket) -> Result<(), AuthDispatchError>;
    fn get_game_server_state(&mut self, packet: AuthPacket) -> Result<(), AuthDispatchError>;
    fn get_channel_list(&mut self, packet: AuthPacket) -> Result<(), AuthDispatchError>;
    fn user_leave(&mut self, packet: AuthPacket) -> Result<(), AuthDispatchError>;
    fn get_user_info(&mut self, packet: AuthPacket) -> Result<(), AuthDispatchError>;
    fn get_inventory_info(&mut self, packet: AuthPacket) -> Result<(), AuthDispatchError>;
    fn get_option(&mut self, packet: AuthPacket) -> Result<(), AuthDispatchError>;
    fn unknown(&mut self, packet: AuthPacket) -> Result<(), AuthDispatchError>;
}

/// Route one seed-validated packet to its Auth handler.
pub fn dispatch_auth_packet(
    handlers: &mut impl AuthHandlers,
    packet: AuthPacket,
) -> Result<(), AuthDispatchError> {
    match packet.opcode {
        AuthOpcode::Login => handlers.login(packet),
        AuthOpcode::KeepAlive => handlers.keep_alive(packet),
        AuthOpcode::GetPointCash => handlers.get_point_cash(packet),
        AuthOpcode::GetGameServerState => handlers.get_game_server_state(packet),
        AuthOpcode::GetChannelList => handlers.get_channel_list(packet),
        AuthOpcode::UserLeave => handlers.user_leave(packet),
        AuthOpcode::GetUserInfo => handlers.get_user_info(packet),
        AuthOpcode::GetInventoryInfo => handlers.get_inventory_info(packet),
        AuthOpcode::GetOption => handlers.get_option(packet),
        AuthOpcode::Unknown(_) => handlers.unknown(packet),
    }
}
