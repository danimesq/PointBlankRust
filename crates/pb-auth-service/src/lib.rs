//! Point Blank Auth business service, independent from TCP and database drivers.
//! The host implements AuthRepository with the production database and Game-session bridge.

use pb_auth::{error_code, login_ack, point_cash_ack, validate_key, LoginIdentity, LoginRequest};
use std::{
    collections::HashMap,
    fmt,
    sync::Mutex,
    time::{Duration, Instant},
};

pub const STATUS_AUTH: u32 = 0xff00_ffff;
pub const STATUS_NONE: u32 = 0xffff_ffff;
const IP_LOGIN_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub player_id: u64,
    pub username: String,
    pub password: String,
    pub rank: i32,
    pub gold: u32,
    pub cash: u32,
    pub tags: u32,
    pub access: i32,
    pub online: bool,
    pub clan_id: u32,
    pub ban_object_id: u64,
    pub status: u32,
}
impl Account {
    pub fn auth_level(&self) -> i32 {
        if self.access == -1 {
            -1
        } else if self.access >= 100 {
            100
        } else if self.access >= 50 {
            50
        } else {
            match self.rank {
                58 => 100,
                59 => 50,
                _ => 0,
            }
        }
    }
    fn identity(&self) -> LoginIdentity {
        LoginIdentity {
            player_id: self.player_id,
            username: self.username.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanStatus {
    pub mac: bool,
    pub ip: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfig {
    pub min_user_size: usize,
    pub max_user_size: usize,
    pub min_password_size: usize,
    pub test_mode: bool,
    pub client_version: String,
    pub access_user_file_list: bool,
    pub user_file_list: String,
    pub channel_only_gm: bool,
    pub enable_clan: bool,
    pub enable_ticket: bool,
    pub enable_tags: bool,
    pub enable_playtime: bool,
    pub playtime_event_running: bool,
}
impl AuthConfig {
    pub fn features(&self) -> u32 {
        let mut f = 0x87fd_776e_u32;
        if !self.enable_clan {
            f = f.wrapping_sub(0x1000);
        }
        if !self.enable_ticket {
            f = f.wrapping_sub(0x4000);
        }
        if !self.enable_tags {
            f = f.wrapping_sub(0x0400_0000);
        }
        if !self.enable_playtime || !self.playtime_event_running {
            f = f.wrapping_sub(0x100);
        }
        f
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepositoryError {
    Unavailable(String),
    Conflict(String),
}
impl fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(s) => write!(f, "Auth repository unavailable: {s}"),
            Self::Conflict(s) => write!(f, "Auth repository conflict: {s}"),
        }
    }
}
impl std::error::Error for RepositoryError {}

/// The implementation must hash/compare the raw client token like the WebPort,
/// ignore stored hashes as credentials, and make claim_login an atomic compare-and-set.
pub trait AuthRepository: Send + Sync {
    fn lookup_token(&self, client_token_base64: &str) -> Result<Option<Account>, RepositoryError>;
    fn active_ban_for_player(&self, player_id: u64) -> Result<Option<(u64, i64)>, RepositoryError>;
    fn is_permanently_banned(&self, account: &Account) -> Result<bool, RepositoryError>;
    fn persist_ban_object_id(&self, player_id: u64, object_id: u64) -> Result<(), RepositoryError>;
    fn update_mac_address(&self, player_id: u64, mac: &str) -> Result<(), RepositoryError>;
    fn ban_status(&self, mac_upper_hex: &str, ip: &str) -> Result<BanStatus, RepositoryError>;
    fn account_ban_expiry(&self, object_id: u64) -> Result<Option<i64>, RepositoryError>;
    fn handle_existing_login(&self, account: &Account) -> Result<(), RepositoryError>;
    fn prepare_successful_login(&self, player_id: u64) -> Result<(), RepositoryError>;
    /// Atomically writes MAC, status=STATUS_AUTH and online=true only if still offline.
    fn claim_login(&self, player_id: u64, mac: &str) -> Result<bool, RepositoryError>;
    fn mint_enter_ticket(&self, player_id: u64) -> Result<String, RepositoryError>;
    /// Release online ownership when the authenticated transport session is destroyed.
    fn release_login(&self, player_id: u64) -> Result<(), RepositoryError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseMode {
    Soft { delay: Duration },
    Destroy { delay: Duration },
    KeepOpen,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginOutcome {
    pub packets: Vec<Vec<u8>>,
    /// Out-of-band WebSocket enter-ticket frame. Never inject this into the PB byte stream.
    pub enter_ticket: Option<String>,
    pub close: CloseMode,
    pub authenticated_player: Option<u64>,
}
impl LoginOutcome {
    fn close(packet: Option<Vec<u8>>, mode: CloseMode) -> Self {
        Self {
            packets: packet.into_iter().collect(),
            enter_ticket: None,
            close: mode,
            authenticated_player: None,
        }
    }
}
#[derive(Debug)]
pub enum LoginError {
    Repository(RepositoryError),
    RateLimiterPoisoned,
}
impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Repository(e) => e.fmt(f),
            Self::RateLimiterPoisoned => f.write_str("LOGIN rate limiter lock poisoned"),
        }
    }
}
impl std::error::Error for LoginError {}
impl From<RepositoryError> for LoginError {
    fn from(e: RepositoryError) -> Self {
        Self::Repository(e)
    }
}

#[derive(Default)]
pub struct LoginRateLimiter {
    last: Mutex<HashMap<String, Instant>>,
}
impl LoginRateLimiter {
    pub fn check(&self, ip: &str, now: Instant) -> Result<bool, LoginError> {
        let mut map = self
            .last
            .lock()
            .map_err(|_| LoginError::RateLimiterPoisoned)?;
        let previous = map.insert(ip.to_owned(), now);
        Ok(match previous {
            None => true,
            Some(t) => now.saturating_duration_since(t) >= IP_LOGIN_INTERVAL,
        })
    }
}

pub struct AuthService<R> {
    repository: R,
    limiter: LoginRateLimiter,
}
impl<R: AuthRepository> AuthService<R> {
    pub fn new(repository: R) -> Self {
        Self {
            repository,
            limiter: LoginRateLimiter::default(),
        }
    }
    pub fn repository(&self) -> &R {
        &self.repository
    }

    /// Clear Auth online ownership after a destructive disconnect.
    pub fn release_login(&self, player_id: u64) -> Result<(), LoginError> {
        self.repository.release_login(player_id).map_err(LoginError::from)
    }

    /// unix_time_ms is wall-clock UTC for ban expiry; monotonic_now is only for throttling.
    pub fn login(
        &self,
        req: LoginRequest,
        ip: &str,
        session_id: u32,
        config: &AuthConfig,
        unix_time_ms: i64,
        monotonic_now: Instant,
    ) -> Result<LoginOutcome, LoginError> {
        if !self.limiter.check(ip, monotonic_now)? {
            return Ok(LoginOutcome::close(
                None,
                CloseMode::Soft {
                    delay: Duration::from_secs(1),
                },
            ));
        }
        let Some(mut account) = self.repository.lookup_token(&req.token)? else {
            return Ok(LoginOutcome::close(
                Some(login_ack(
                    error_code::LOGIN_ID_PASS_INCORRECT,
                    0,
                    config.features(),
                    None,
                )),
                CloseMode::Soft {
                    delay: Duration::from_secs(1),
                },
            ));
        };

        let valid = account.username.len() >= config.min_user_size
            && account.username.len() <= config.max_user_size
            && (config.test_mode || account.password.len() >= config.min_password_size)
            && req.mac.iter().any(|b| *b != 0)
            && req.client_version_string() == config.client_version
            && (!config.access_user_file_list || req.user_file_list == config.user_file_list)
            && req.resolution != (0, 0);
        if !valid {
            return Ok(LoginOutcome::close(
                Some(pb_auth::disconnection_success_ack(
                    error_code::DISCONNECT_INVALID_LOGIN,
                )),
                CloseMode::Destroy {
                    delay: Duration::from_secs(1),
                },
            ));
        }

        if let Some((object_id, expires)) =
            self.repository.active_ban_for_player(account.player_id)?
        {
            if expires > unix_time_ms {
                if account.ban_object_id != object_id {
                    self.repository
                        .persist_ban_object_id(account.player_id, object_id)?;
                    account.ban_object_id = object_id;
                }
                return Ok(self.deny(&account, error_code::LOGIN_BLOCK_ACCOUNT, config));
            }
        }
        if self.repository.is_permanently_banned(&account)? {
            return Ok(self.deny(&account, error_code::LOGIN_BLOCK_ACCOUNT, config));
        }

        let mac_storage = format_mac(&req.mac, Some(':'), false);
        self.repository
            .update_mac_address(account.player_id, &mac_storage)?;
        let bans = self
            .repository
            .ban_status(&format_mac(&req.mac, None, true), ip)?;
        if bans.mac || bans.ip {
            let code = if bans.ip {
                error_code::LOGIN_BLOCK_IP
            } else {
                error_code::LOGIN_BLOCK_ACCOUNT
            };
            return Ok(self.deny(&account, code, config));
        }

        let level = account.auth_level();
        if !((level > 0 && config.channel_only_gm) || (level >= 0 && !config.channel_only_gm)) {
            return Ok(self.deny(&account, error_code::LOGIN_TIME_OUT_2, config));
        }

        if account.online {
            let outcome = self.already_online(&account, config);
            self.repository.handle_existing_login(&account)?;
            return Ok(outcome);
        }
        if account.ban_object_id > 0 {
            if let Some(expires) = self.repository.account_ban_expiry(account.ban_object_id)? {
                if expires > unix_time_ms {
                    return Ok(self.deny(&account, error_code::LOGIN_BLOCK_ACCOUNT, config));
                }
            }
        }

        self.repository
            .prepare_successful_login(account.player_id)?;
        // Mint before claiming online so a ticket-signing failure cannot strand
        // the account in online=true. A losing concurrent attempt simply drops
        // its unused ticket after the atomic compare-and-set fails.
        let ticket = self.repository.mint_enter_ticket(account.player_id)?;
        if !self
            .repository
            .claim_login(account.player_id, &mac_storage)?
        {
            let latest = self.repository.lookup_token(&req.token)?.unwrap_or(account);
            let outcome = self.already_online(&latest, config);
            self.repository.handle_existing_login(&latest)?;
            return Ok(outcome);
        }
        let key = validate_key(account.player_id, session_id, req.hw_spec0);
        Ok(LoginOutcome {
            packets: vec![
                login_ack(
                    error_code::SUCCESS,
                    key,
                    config.features(),
                    Some(&account.identity()),
                ),
                point_cash_ack(0, account.cash, account.gold, account.tags),
            ],
            enter_ticket: Some(ticket),
            close: CloseMode::KeepOpen,
            authenticated_player: Some(account.player_id),
        })
    }

    fn deny(&self, account: &Account, code: u32, config: &AuthConfig) -> LoginOutcome {
        LoginOutcome::close(
            Some(login_ack(
                code,
                0,
                config.features(),
                Some(&account.identity()),
            )),
            CloseMode::Soft {
                delay: Duration::from_secs(1),
            },
        )
    }
    fn already_online(&self, account: &Account, config: &AuthConfig) -> LoginOutcome {
        LoginOutcome::close(
            Some(login_ack(
                error_code::LOGIN_ALREADY_LOGIN,
                0,
                config.features(),
                Some(&account.identity()),
            )),
            CloseMode::Soft {
                delay: Duration::from_secs(1),
            },
        )
    }
}

fn format_mac(mac: &[u8; 6], separator: Option<char>, upper: bool) -> String {
    let mut out = String::with_capacity(17);
    for (i, b) in mac.iter().enumerate() {
        if i > 0 {
            if let Some(sep) = separator {
                out.push(sep);
            }
        }
        if upper {
            out.push_str(&format!("{b:02X}"));
        } else {
            out.push_str(&format!("{b:02x}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct FakeRepo {
        online: AtomicBool,
        lookups: AtomicUsize,
        bans: BanStatus,
        permanent: bool,
        active: Option<(u64, i64)>,
    }
    impl FakeRepo {
        fn new() -> Self {
            Self {
                online: AtomicBool::new(false),
                lookups: AtomicUsize::new(0),
                bans: BanStatus {
                    mac: false,
                    ip: false,
                },
                permanent: false,
                active: None,
            }
        }
    }
    impl AuthRepository for FakeRepo {
        fn lookup_token(&self, t: &str) -> Result<Option<Account>, RepositoryError> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            Ok((t == "dG9rZW4=").then(|| Account {
                player_id: 126,
                username: "w17abc".into(),
                password: "password".into(),
                rank: 1,
                gold: 20,
                cash: 30,
                tags: 4,
                access: 0,
                online: self.online.load(Ordering::SeqCst),
                clan_id: 0,
                ban_object_id: 0,
                status: STATUS_NONE,
            }))
        }
        fn active_ban_for_player(&self, _: u64) -> Result<Option<(u64, i64)>, RepositoryError> {
            Ok(self.active)
        }
        fn is_permanently_banned(&self, _: &Account) -> Result<bool, RepositoryError> {
            Ok(self.permanent)
        }
        fn persist_ban_object_id(&self, _: u64, _: u64) -> Result<(), RepositoryError> {
            Ok(())
        }
        fn update_mac_address(&self, _: u64, _: &str) -> Result<(), RepositoryError> {
            Ok(())
        }
        fn ban_status(&self, _: &str, _: &str) -> Result<BanStatus, RepositoryError> {
            Ok(self.bans)
        }
        fn account_ban_expiry(&self, _: u64) -> Result<Option<i64>, RepositoryError> {
            Ok(None)
        }
        fn handle_existing_login(&self, _: &Account) -> Result<(), RepositoryError> {
            Ok(())
        }
        fn prepare_successful_login(&self, _: u64) -> Result<(), RepositoryError> {
            Ok(())
        }
        fn claim_login(&self, _: u64, _: &str) -> Result<bool, RepositoryError> {
            Ok(!self.online.swap(true, Ordering::SeqCst))
        }
        fn mint_enter_ticket(&self, _: u64) -> Result<String, RepositoryError> {
            Ok("signed-ticket".into())
        }
        fn release_login(&self, _: u64) -> Result<(), RepositoryError> { Ok(()) }
    }
    fn request() -> LoginRequest {
        LoginRequest {
            hw_spec0: 0x02424557,
            mac: [1, 2, 3, 4, 5, 6],
            resolution: (1920, 1080),
            user_file_list: "files".into(),
            locale: 1,
            client_version: (5, 42),
            token: "dG9rZW4=".into(),
        }
    }
    fn config() -> AuthConfig {
        AuthConfig {
            min_user_size: 4,
            max_user_size: 16,
            min_password_size: 4,
            test_mode: false,
            client_version: "5.42".into(),
            access_user_file_list: true,
            user_file_list: "files".into(),
            channel_only_gm: false,
            enable_clan: true,
            enable_ticket: true,
            enable_tags: true,
            enable_playtime: true,
            playtime_event_running: true,
        }
    }
    fn code(packet: &[u8]) -> u32 {
        u32::from_le_bytes(packet[packet.len() - 4..].try_into().unwrap())
    }

    #[test]
    fn successful_login_emits_login_ack_cash_ack_and_ticket() {
        let service = AuthService::new(FakeRepo::new());
        let out = service
            .login(
                request(),
                "203.0.113.1",
                7,
                &config(),
                1_800_000_000_000,
                Instant::now(),
            )
            .unwrap();
        assert_eq!(out.packets.len(), 2);
        assert_eq!(
            u16::from_le_bytes([out.packets[0][0], out.packets[0][1]]),
            1283
        );
        assert_eq!(
            u16::from_le_bytes([out.packets[1][0], out.packets[1][1]]),
            1061
        );
        assert_eq!(out.enter_ticket.as_deref(), Some("signed-ticket"));
        assert_eq!(out.authenticated_player, Some(126));
        assert_eq!(out.close, CloseMode::KeepOpen);
    }
    #[test]
    fn invalid_token_and_invalid_version_match_distinct_reference_responses() {
        let service = AuthService::new(FakeRepo::new());
        let mut bad = request();
        bad.token = "nope".into();
        let out = service
            .login(bad, "a", 1, &config(), 1, Instant::now())
            .unwrap();
        assert_eq!(code(&out.packets[0]), error_code::LOGIN_ID_PASS_INCORRECT);
        let service = AuthService::new(FakeRepo::new());
        let mut bad = request();
        bad.client_version = (1, 0);
        let out = service
            .login(bad, "b", 1, &config(), 1, Instant::now())
            .unwrap();
        assert_eq!(
            u16::from_le_bytes([out.packets[0][0], out.packets[0][1]]),
            3074
        );
    }
    #[test]
    fn mac_ip_and_account_bans_are_enforced() {
        let mut repo = FakeRepo::new();
        repo.bans.mac = true;
        let service = AuthService::new(repo);
        let out = service
            .login(request(), "c", 1, &config(), 1, Instant::now())
            .unwrap();
        assert_eq!(code(&out.packets[0]), error_code::LOGIN_BLOCK_ACCOUNT);
        let mut repo = FakeRepo::new();
        repo.bans.ip = true;
        let service = AuthService::new(repo);
        let out = service
            .login(request(), "d", 1, &config(), 1, Instant::now())
            .unwrap();
        assert_eq!(code(&out.packets[0]), error_code::LOGIN_BLOCK_IP);
        let mut repo = FakeRepo::new();
        repo.active = Some((55, 2_000));
        let service = AuthService::new(repo);
        let out = service
            .login(request(), "e", 1, &config(), 1_000, Instant::now())
            .unwrap();
        assert_eq!(code(&out.packets[0]), error_code::LOGIN_BLOCK_ACCOUNT);
    }
    #[test]
    fn channel_only_gm_policy_and_duplicate_ip_throttle_are_enforced() {
        let mut cfg = config();
        cfg.channel_only_gm = true;
        let service = AuthService::new(FakeRepo::new());
        let out = service
            .login(request(), "f", 1, &cfg, 1, Instant::now())
            .unwrap();
        assert_eq!(code(&out.packets[0]), error_code::LOGIN_TIME_OUT_2);
        let repo = FakeRepo::new();
        let service = AuthService::new(repo);
        let now = Instant::now();
        let _ = service
            .login(request(), "same-ip", 1, &config(), 1, now)
            .unwrap();
        let out = service
            .login(
                request(),
                "same-ip",
                2,
                &config(),
                1,
                now + Duration::from_millis(100),
            )
            .unwrap();
        assert!(out.packets.is_empty());
        assert_eq!(service.repository.lookups.load(Ordering::SeqCst), 1);
    }
}
