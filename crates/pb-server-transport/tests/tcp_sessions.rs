use pb_protocol::framing::Frame;
use pb_server_transport::{SessionInfo, SessionWriter, TcpServer, TcpServerConfig, TcpSessionHandler};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Default)]
struct Recorder {
    connected: Mutex<Vec<u64>>,
    frames: Mutex<Vec<(u64, Vec<u8>, bool)>>,
    disconnected: Mutex<Vec<u64>>,
}
impl TcpSessionHandler for Recorder {
    fn on_connect(&self, session: &SessionInfo, _writer: &SessionWriter) {
        self.connected.lock().unwrap().push(session.id);
    }
    fn on_frame(&self, session: &SessionInfo, frame: Frame, writer: &SessionWriter) {
        self.frames.lock().unwrap().push((session.id, frame.payload.clone(), frame.encrypted));
        writer.send_plain(&[0x34, 0x12, 0xaa]).unwrap();
    }
    fn on_disconnect(&self, session: &SessionInfo) {
        self.disconnected.lock().unwrap().push(session.id);
    }
}
fn config() -> TcpServerConfig {
    TcpServerConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        max_connections: 4,
        read_timeout: Duration::from_millis(50),
        max_frames_per_read: 8,
    }
}

#[test]
fn accepts_sessions_decodes_frames_and_sends_server_frames() {
    let handler = Arc::new(Recorder::default());
    let server = Arc::new(TcpServer::bind(config(), handler.clone()).unwrap());
    let addr = server.local_addr().unwrap();
    let runner = {
        let server = server.clone();
        thread::spawn(move || server.run().unwrap())
    };
    let mut client = TcpStream::connect(addr).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let input = [4, 0, 0x11, 0x22, 0, 0, 0, 0, 0];
    client.write_all(&input[..3]).unwrap();
    thread::sleep(Duration::from_millis(10));
    client.write_all(&input[3..]).unwrap();

    let mut response = [0u8; 10];
    client.read_exact(&mut response).unwrap();
    assert_eq!(&response[..2], &[5, 0]);
    assert_eq!(&response[2..5], &[0x34, 0x12, 0xaa]);
    assert_eq!(&response[5..], &[0; 5]);

    let frames = handler.frames.lock().unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].1, [0x11, 0x22, 0, 0]);
    assert!(!frames[0].2);
    drop(frames);

    drop(client);
    thread::sleep(Duration::from_millis(30));
    server.shutdown();
    runner.join().unwrap();
    assert_eq!(handler.connected.lock().unwrap().len(), 1);
    assert_eq!(handler.disconnected.lock().unwrap().len(), 1);
}

#[test]
fn rejects_zero_connection_limit() {
    let mut cfg = config();
    cfg.max_connections = 0;
    assert!(TcpServer::bind(cfg, Arc::new(Recorder::default())).is_err());
}
#[test]
fn rejects_zero_frame_limit() {
    let mut cfg = config();
    cfg.max_frames_per_read = 0;
    assert!(TcpServer::bind(cfg, Arc::new(Recorder::default())).is_err());
}
