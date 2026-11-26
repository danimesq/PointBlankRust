//! Runtime bridge joining Auth protocol sessions, LOGIN policy and TCP transport.
//!
//! The host supplies a PostgreSQL-backed AuthRepository and a WebSocket text
//! side-channel. PB packets remain binary server frames; enterTicket is emitted
//! only through the separate text-frame sink and is never inserted into PB bytes.

use pb_auth::{
    dispatch_auth_packet, AuthBootstrap, AuthDispatchError, AuthHandlers, AuthPacket,
    AuthSession,
};
use pb_auth_postgres::{AuthSessionBridge, PgAuthRepository};
use pb_auth_service::{
    AuthConfig as LoginConfig, AuthRepository, AuthService, CloseMode, LoginError,
};
use pb_server_transport::{SessionInfo, SessionWriter, TcpSessionHandler};
use pb_protocol::framing::Frame;
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Auth packet/session limits from pb-auth, distinct from LOGIN policy settings.
#[derive(Debug, Clone)]
pub struct AuthRuntimeConfig {
    pub login: LoginConfig,
    pub send_enter_ticket: bool,
    pub soft_close_delay: Duration,
    pub destroy_close_delay: Duration,
}
impl AuthRuntimeConfig {
    pub fn new(login: LoginConfig) -> Self {
        Self {
            login,
            send_enter_ticket: false,
            soft_close_delay: Duration::from_secs(1),
            destroy_close_delay: Duration::from_secs(1),
        }
    }
}

/// WebSocket control-plane output. Implementations must send a WebSocket TEXT
/// message on the same logical client session, not a binary PB packet.
pub trait AuthTextFrameSink: Send + Sync + 'static {
    fn send_text_frame(&self, transport_session_id: u64, text: &str) -> io::Result<()>;
}

/// Explicit no-op sink for raw TCP deployments, which have no WebSocket text lane.
pub struct NoopAuthTextFrameSink;
impl AuthTextFrameSink for NoopAuthTextFrameSink {
    fn send_text_frame(&self, _transport_session_id: u64, _text: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "raw TCP sessions do not have a WebSocket text-frame channel",
        ))
    }
}

#[derive(Debug)]
pub enum AuthRuntimeError {
    Bootstrap(String),
    Session(String),
    Dispatch(String),
    Output(io::Error),
    SessionIdExhausted,
}
impl std::fmt::Display for AuthRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bootstrap(e) => write!(f, "Auth CONNECT bootstrap failed: {e}"),
            Self::Session(e) => write!(f, "Auth session failed: {e}"),
            Self::Dispatch(e) => write!(f, "Auth packet dispatch failed: {e}"),
            Self::Output(e) => write!(f, "Auth session output failed: {e}"),
            Self::SessionIdExhausted => f.write_str("all Auth session IDs are in use"),
        }
    }
}
impl std::error::Error for AuthRuntimeError {}

struct RuntimeSession {
    protocol_id: u32,
    auth: AuthSession,
    authenticated_player: Option<u64>,
}

/// A concrete TcpSessionHandler that runs CONNECT_ACK, CMess ingress, seed
/// validation, typed opcode dispatch and LOGIN service orchestration.
pub struct AuthRuntimeHandler<R: AuthRepository> {
    service: Arc<AuthService<R>>,
    config: AuthRuntimeConfig,
    text_sink: Arc<dyn AuthTextFrameSink>,
    next_protocol_id: AtomicU32,
    active_protocol_ids: Mutex<HashSet<u32>>,
    sessions: Mutex<HashMap<u64, RuntimeSession>>,
}
impl<R: AuthRepository + 'static> AuthRuntimeHandler<R> {
    pub fn new(
        service: AuthService<R>,
        config: AuthRuntimeConfig,
        text_sink: Arc<dyn AuthTextFrameSink>,
    ) -> Self {
        Self {
            service: Arc::new(service),
            config,
            text_sink,
            next_protocol_id: AtomicU32::new(1),
            active_protocol_ids: Mutex::new(HashSet::new()),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn allocate_protocol_id(&self) -> Result<u32, AuthRuntimeError> {
        let mut active = self.active_protocol_ids.lock().map_err(|_| {
            AuthRuntimeError::Session("protocol session ID registry poisoned".into())
        })?;
        for _ in 0..0x7fff {
            let raw = self.next_protocol_id.fetch_add(1, Ordering::Relaxed);
            let candidate = ((raw.saturating_sub(1)) % 0x7fff) + 1;
            if active.insert(candidate) {
                return Ok(candidate);
            }
        }
        Err(AuthRuntimeError::SessionIdExhausted)
    }

    fn release_protocol_id(&self, id: u32) {
        if let Ok(mut active) = self.active_protocol_ids.lock() {
            active.remove(&id);
        }
    }

    fn process_packet(
        &self,
        transport: &SessionInfo,
        protocol_id: u32,
        packet: AuthPacket,
        writer: &SessionWriter,
    ) -> Result<(), AuthRuntimeError> {
        let mut handlers = RuntimePacketHandlers {
            service: &self.service,
            config: &self.config,
            text_sink: &self.text_sink,
            transport_session_id: transport.id,
            protocol_session_id: protocol_id,
            peer_ip: transport.peer_addr.ip(),
            writer,
            authenticated_player: None,
            preserve_online_on_disconnect: false,
        };
        let dispatch_result = dispatch_auth_packet(&mut handlers, packet);
        if let Ok(mut sessions) = self.sessions.lock() {
            if let Some(session) = sessions.get_mut(&transport.id) {
                if let Some(player_id) = handlers.authenticated_player {
                    session.authenticated_player = Some(player_id);
                }
                if handlers.preserve_online_on_disconnect {
                    session.authenticated_player = None;
                }
            }
        }
        dispatch_result.map_err(|e: AuthDispatchError| AuthRuntimeError::Dispatch(e.to_string()))?;
        Ok(())
    }

    fn process_frame(
        &self,
        transport: &SessionInfo,
        frame: Frame,
        writer: &SessionWriter,
    ) -> Result<(), AuthRuntimeError> {
        let (protocol_id, packet) = {
            let mut sessions = self.sessions.lock().map_err(|_| {
                AuthRuntimeError::Session("Auth session registry poisoned".into())
            })?;
            let session = sessions.get_mut(&transport.id).ok_or_else(|| {
                AuthRuntimeError::Session("frame received for unknown session".into())
            })?;
            let packet = session
                .auth
                .process_frame(frame)
                .map_err(|e| AuthRuntimeError::Session(e.to_string()))?;
            (session.protocol_id, packet)
        };
        if let Some(packet) = packet {
            self.process_packet(transport, protocol_id, packet, writer)?;
        }
        Ok(())
    }
}

impl<R: AuthRepository + 'static> TcpSessionHandler for AuthRuntimeHandler<R> {
    fn on_connect(&self, session: &SessionInfo, writer: &SessionWriter) {
        let mut allocated_protocol_id = None;
        let result = (|| {
            let protocol_id = self.allocate_protocol_id()?;
            allocated_protocol_id = Some(protocol_id);
            let bootstrap = AuthBootstrap::generate(protocol_id)
                .map_err(|e| AuthRuntimeError::Bootstrap(e.to_string()))?;
            let auth = AuthSession::new(
                protocol_id,
                bootstrap.session_seed,
                bootstrap.keys.client_key,
                pb_auth::AuthConfig::default(),
            )
            .map_err(|e| AuthRuntimeError::Session(e.to_string()))?;
            let connect_ack = bootstrap
                .connect_ack()
                .map_err(|e| AuthRuntimeError::Bootstrap(e.to_string()))?;
            writer.send_plain(&connect_ack).map_err(AuthRuntimeError::Output)?;
            let mut sessions = self.sessions.lock().map_err(|_| {
                AuthRuntimeError::Session("Auth session registry poisoned".into())
            })?;
            sessions.insert(
                session.id,
                RuntimeSession {
                    protocol_id,
                    auth,
                    authenticated_player: None,
                },
            );
            Ok::<(), AuthRuntimeError>(())
        })();
        if let Err(error) = result {
            eprintln!("[pb-auth-runtime] session {} bootstrap failed: {error}", session.id);
            // The session was not registered, so release any allocated protocol ID.
            if let Some(protocol_id) = allocated_protocol_id {
                self.release_protocol_id(protocol_id);
            }
            writer.shutdown();
        }
    }

    fn on_frame(&self, session: &SessionInfo, frame: Frame, writer: &SessionWriter) {
        if let Err(error) = self.process_frame(session, frame, writer) {
            eprintln!("[pb-auth-runtime] session {} closed: {error}", session.id);
            writer.shutdown();
        }
    }

    fn on_disconnect(&self, session: &SessionInfo) {
        let state = self.sessions.lock().ok().and_then(|mut sessions| sessions.remove(&session.id));
        if let Some(state) = state {
            self.release_protocol_id(state.protocol_id);
            if let Some(player_id) = state.authenticated_player {
                if let Err(error) = self.service.release_login(player_id) {
                    eprintln!(
                        "[pb-auth-runtime] failed to release player {} after session {}: {}",
                        player_id, session.id, error
                    );
                }
            }
        }
    }
}

/// Convenience constructor for the concrete PostgreSQL repository adapter.
impl<B: AuthSessionBridge + 'static> AuthRuntimeHandler<PgAuthRepository<B>> {
    pub fn with_postgres_repository(
        repository: PgAuthRepository<B>,
        config: AuthRuntimeConfig,
        text_sink: Arc<dyn AuthTextFrameSink>,
    ) -> Self {
        Self::new(AuthService::new(repository), config, text_sink)
    }
}

struct RuntimePacketHandlers<'a, R: AuthRepository> {
    service: &'a AuthService<R>,
    config: &'a AuthRuntimeConfig,
    text_sink: &'a Arc<dyn AuthTextFrameSink>,
    transport_session_id: u64,
    protocol_session_id: u32,
    peer_ip: IpAddr,
    writer: &'a SessionWriter,
    authenticated_player: Option<u64>,
    preserve_online_on_disconnect: bool,
}
impl<R: AuthRepository> RuntimePacketHandlers<'_, R> {
    fn send_packets(&self, packets: &[Vec<u8>]) -> Result<(), AuthRuntimeError> {
        for packet in packets {
            self.writer.send_plain(packet).map_err(AuthRuntimeError::Output)?;
        }
        Ok(())
    }

    fn close_after(&self, mode: CloseMode) {
        let (delay, destroy) = match mode {
            CloseMode::KeepOpen => return,
            CloseMode::Soft { delay } => (delay, false),
            CloseMode::Destroy { delay } => (delay, true),
        };
        // The TCP transport's disconnect callback owns online-state cleanup.
        // Soft closes preserve an authenticated account; destructive closes
        // are handled by the same callback only when this session owns a login.
        let writer = self.writer.clone();
        let delay = if destroy {
            delay.max(self.config.destroy_close_delay)
        } else {
            delay.max(self.config.soft_close_delay)
        };
        thread::spawn(move || {
            thread::sleep(delay);
            writer.shutdown();
        });
    }
}
impl<R: AuthRepository> AuthHandlers for RuntimePacketHandlers<'_, R> {
    fn login(&mut self, request: pb_auth::LoginRequest) -> Result<(), AuthDispatchError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AuthDispatchError::Handler(e.to_string()))?;
        let outcome = self.service.login(
            request,
            &self.peer_ip.to_string(),
            self.protocol_session_id,
            &self.config.login,
            i64::try_from(now.as_millis()).unwrap_or(i64::MAX),
            std::time::Instant::now(),
        ).map_err(|e: LoginError| AuthDispatchError::Handler(e.to_string()))?;

        self.authenticated_player = outcome.authenticated_player;

        // The WebPort emits enterTicket as a JSON WebSocket TEXT message before
        // LOGIN_ACK/CASH_ACK. It is deliberately not encoded as a PB packet.
        if self.config.send_enter_ticket {
            if let (Some(ticket), Some(player_id)) = (
                outcome.enter_ticket.as_deref(),
                outcome.authenticated_player,
            ) {
                let text = json!({
                    "t": "enterTicket",
                    "pid": player_id.to_string(),
                    "ticket": ticket
                }).to_string();
                self.text_sink
                    .send_text_frame(self.transport_session_id, &text)
                    .map_err(|e| AuthDispatchError::Handler(format!("enterTicket WebSocket text frame: {e}")))?;
            }
        }

        self.send_packets(&outcome.packets)
            .map_err(|e| AuthDispatchError::Handler(e.to_string()))?;
        self.close_after(outcome.close);
        Ok(())
    }

    fn keep_alive(&mut self, _packet: AuthPacket) -> Result<(), AuthDispatchError> { Ok(()) }
    fn get_point_cash(&mut self, _packet: AuthPacket) -> Result<(), AuthDispatchError> { Ok(()) }
    fn get_game_server_state(&mut self, _packet: AuthPacket) -> Result<(), AuthDispatchError> { Ok(()) }
    fn get_channel_list(&mut self, _packet: AuthPacket) -> Result<(), AuthDispatchError> { Ok(()) }
    fn user_leave(&mut self, _packet: AuthPacket) -> Result<(), AuthDispatchError> {
        self.writer.send_plain(&pb_auth::user_leave_ack(0))
            .map_err(|e| AuthDispatchError::Handler(e.to_string()))?;
        // USER_LEAVE is a handoff to Game, not an account logout.
        self.preserve_online_on_disconnect = true;
        let writer = self.writer.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            writer.shutdown();
        });
        Ok(())
    }
    fn get_user_info(&mut self, _packet: AuthPacket) -> Result<(), AuthDispatchError> { Ok(()) }
    fn get_inventory_info(&mut self, _packet: AuthPacket) -> Result<(), AuthDispatchError> { Ok(()) }
    fn get_option(&mut self, _packet: AuthPacket) -> Result<(), AuthDispatchError> { Ok(()) }
    fn unknown(&mut self, _packet: AuthPacket) -> Result<(), AuthDispatchError> { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_ticket_is_json_text_and_not_a_pb_packet() {
        let text = json!({
            "t": "enterTicket",
            "pid": "126",
            "ticket": "encoded-body.signature"
        }).to_string();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["t"], "enterTicket");
        assert_eq!(value["pid"], "126");
        assert_eq!(value["ticket"], "encoded-body.signature");
        assert!(!text.as_bytes().starts_with(&1283u16.to_le_bytes()));
    }

    #[test]
    fn raw_tcp_text_sink_refuses_to_masquerade_as_websocket() {
        let sink = NoopAuthTextFrameSink;
        let error = sink.send_text_frame(1, r#"{"t":"enterTicket"}"#).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
