//! TCP connection transport for Point Blank server endpoints.
//!
//! This crate owns sockets, connection lifecycle and stream framing only.
//! Authentication owns key exchange, CMess/session keys and seed validation;
//! Auth/Game own packet meaning and application state.

use pb_protocol::framing::{build_plain_server_frame, Frame, FrameDecoder};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Runtime limits for one TCP listener.
#[derive(Debug, Clone)]
pub struct TcpServerConfig {
    pub bind_addr: SocketAddr,
    pub max_connections: usize,
    pub read_timeout: Duration,
    pub max_frames_per_read: usize,
}

impl Default for TcpServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            max_connections: 1024,
            read_timeout: Duration::from_secs(1),
            max_frames_per_read: 32,
        }
    }
}

/// Stable identity and peer address for one accepted connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: u64,
    pub peer_addr: SocketAddr,
}

/// Errors raised while binding or configuring the listener.
#[derive(Debug)]
pub enum TransportError {
    Io(io::Error),
    InvalidConfig(&'static str),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "TCP transport I/O error: {error}"),
            Self::InvalidConfig(message) => write!(f, "invalid TCP transport config: {message}"),
        }
    }
}
impl std::error::Error for TransportError {}
impl From<io::Error> for TransportError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Cloneable writer for a live session. The caller supplies plaintext or
/// already encrypted bytes, keeping key management outside this crate.
#[derive(Clone)]
pub struct SessionWriter {
    stream: Arc<Mutex<TcpStream>>,
    closed: Arc<AtomicBool>,
}

impl SessionWriter {
    pub fn send_plain(&self, payload: &[u8]) -> io::Result<()> {
        let frame = build_plain_server_frame(payload)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("{error:?}")))?;
        self.send_frame(frame)
    }

    fn send_frame(&self, frame: Vec<u8>) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "session is closed",
            ));
        }
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "session writer lock poisoned"))?;
        stream.write_all(&frame)
    }

    pub fn shutdown(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            if let Ok(stream) = self.stream.lock() {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        }
    }
}

/// Callbacks run serially per connection; separate sessions run concurrently.
pub trait TcpSessionHandler: Send + Sync + 'static {
    fn on_connect(&self, _session: &SessionInfo, _writer: &SessionWriter) {}
    fn on_frame(&self, session: &SessionInfo, frame: Frame, writer: &SessionWriter);
    fn on_disconnect(&self, _session: &SessionInfo) {}
}

/// A bound TCP listener. Run it on a dedicated thread and call shutdown to
/// stop accepting clients and close active sessions.
pub struct TcpServer {
    listener: TcpListener,
    config: TcpServerConfig,
    handler: Arc<dyn TcpSessionHandler>,
    next_session_id: AtomicU64,
    active_connections: Arc<AtomicUsize>,
    shutting_down: Arc<AtomicBool>,
    sessions: Arc<Mutex<HashMap<u64, SessionWriter>>>,
}

impl TcpServer {
    pub fn bind(
        config: TcpServerConfig,
        handler: Arc<dyn TcpSessionHandler>,
    ) -> Result<Self, TransportError> {
        if config.max_connections == 0 {
            return Err(TransportError::InvalidConfig(
                "max_connections must be greater than zero",
            ));
        }
        if config.max_frames_per_read == 0 {
            return Err(TransportError::InvalidConfig(
                "max_frames_per_read must be greater than zero",
            ));
        }
        if config.read_timeout.is_zero() {
            return Err(TransportError::InvalidConfig(
                "read_timeout must be greater than zero",
            ));
        }
        let listener = TcpListener::bind(config.bind_addr)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            config,
            handler,
            next_session_id: AtomicU64::new(1),
            active_connections: Arc::new(AtomicUsize::new(0)),
            shutting_down: Arc::new(AtomicBool::new(false)),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Acquire)
    }

    /// Run the accept loop until shutdown is called.
    pub fn run(&self) -> io::Result<()> {
        while !self.shutting_down.load(Ordering::Acquire) {
            match self.listener.accept() {
                Ok((stream, peer_addr)) => {
                    if !reserve_connection(&self.active_connections, self.config.max_connections) {
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }
                    let session = SessionInfo {
                        id: self.next_session_id.fetch_add(1, Ordering::Relaxed),
                        peer_addr,
                    };
                    let handler = Arc::clone(&self.handler);
                    let sessions = Arc::clone(&self.sessions);
                    let active = Arc::clone(&self.active_connections);
                    let shutting_down = Arc::clone(&self.shutting_down);
                    let timeout = self.config.read_timeout;
                    let max_frames = self.config.max_frames_per_read;
                    if let Err(error) = thread::Builder::new()
                        .name(format!("pb-tcp-session-{}", session.id))
                        .spawn(move || {
                            let _guard = ActiveConnectionGuard(active);
                            serve_session(
                                stream,
                                session,
                                handler,
                                sessions,
                                timeout,
                                max_frames,
                                shutting_down,
                            );
                        })
                    {
                        self.active_connections.fetch_sub(1, Ordering::AcqRel);
                        return Err(error);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Stop accepting clients and close all currently registered sessions.
    pub fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::Release);
        if let Ok(sessions) = self.sessions.lock() {
            for writer in sessions.values() {
                writer.shutdown();
            }
        }
    }
}

fn reserve_connection(active: &AtomicUsize, limit: usize) -> bool {
    active
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            if current < limit {
                Some(current + 1)
            } else {
                None
            }
        })
        .is_ok()
}

struct ActiveConnectionGuard(Arc<AtomicUsize>);
impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn serve_session(
    mut reader: TcpStream,
    session: SessionInfo,
    handler: Arc<dyn TcpSessionHandler>,
    sessions: Arc<Mutex<HashMap<u64, SessionWriter>>>,
    timeout: Duration,
    max_frames_per_read: usize,
    shutting_down: Arc<AtomicBool>,
) {
    let Ok(writer_stream) = reader.try_clone() else {
        return;
    };
    if reader.set_read_timeout(Some(timeout)).is_err() {
        return;
    }
    let writer = SessionWriter {
        stream: Arc::new(Mutex::new(writer_stream)),
        closed: Arc::new(AtomicBool::new(false)),
    };
    if let Ok(mut active) = sessions.lock() {
        active.insert(session.id, writer.clone());
    } else {
        return;
    }
    handler.on_connect(&session, &writer);

    let mut decoder = FrameDecoder::new();
    let mut buffer = [0u8; 8192];
    while !shutting_down.load(Ordering::Acquire) && !writer.closed.load(Ordering::Acquire) {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(length) => {
                let frames = decoder.push(&buffer[..length]);
                if frames.len() > max_frames_per_read {
                    break;
                }
                for frame in frames {
                    if writer.closed.load(Ordering::Acquire) {
                        break;
                    }
                    handler.on_frame(&session, frame, &writer);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(_) => break,
        }
    }

    writer.shutdown();
    if let Ok(mut active) = sessions.lock() {
        active.remove(&session.id);
    }
    handler.on_disconnect(&session);
}
