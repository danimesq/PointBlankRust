//! PostgreSQL adapter for the Point Blank LOGIN service.
//!
//! SQL is aligned with point-blank-webport's db.ts and db/init/001_init.sql.
//! The host supplies a connected postgres::Client (including its chosen TLS
//! configuration) and an AuthSessionBridge for Auth/Game session operations.

use pb_auth_security::EnterTicketSigner;
use pb_auth_service::{
    Account, AuthRepository, BanStatus, RepositoryError, STATUS_AUTH,
};
use postgres::{Client, Error as PostgresError};
use std::{
    sync::{Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

const ACCOUNT_BY_TOKEN_SQL: &str = r#"
    SELECT player_id, username, password, rank, gold, cash, tags, access_level,
           online, clan_id, ban_object_id, status, token
      FROM accounts
     WHERE token = $1 OR token = $2
     LIMIT 1
"#;

/// Operations that cannot be implemented by SQL alone.
///
/// The WebPort keeps active Auth/Game sessions in process memory. Keeping this
/// bridge explicit prevents a database adapter from pretending it can kick a
/// live Game session or load the full account metadata by itself.
pub trait AuthSessionBridge: Send + Sync {
    fn handle_existing_login(&self, account: &Account) -> Result<(), RepositoryError>;
    fn prepare_successful_login(&self, player_id: u64) -> Result<(), RepositoryError>;
}

pub struct PgAuthRepository<B> {
    client: Mutex<Client>,
    sessions: B,
    ticket_signer: EnterTicketSigner,
}

impl<B: AuthSessionBridge> PgAuthRepository<B> {
    /// The supplied client may use NoTls or a TLS connector chosen by the host.
    ///
    /// This initial adapter serializes SQL through one connection. A production
    /// host can later replace this with a pool-backed executor without changing
    /// AuthRepository's behavior.
    pub fn new(client: Client, sessions: B, ticket_signer: EnterTicketSigner) -> Self {
        Self {
            client: Mutex::new(client),
            sessions,
            ticket_signer,
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, Client>, RepositoryError> {
        self.client
            .lock()
            .map_err(|_| RepositoryError::Unavailable("PostgreSQL client lock poisoned".into()))
    }
}

fn db_error(error: PostgresError) -> RepositoryError {
    RepositoryError::Unavailable(error.to_string())
}

fn account_from_row(row: &postgres::Row) -> Result<Account, RepositoryError> {
    let player_id: i64 = row.get("player_id");
    let gold: i32 = row.get("gold");
    let cash: i32 = row.get("cash");
    let tags: i32 = row.get("tags");
    let clan_id: i32 = row.get("clan_id");
    let status: i64 = row.get("status");

    Ok(Account {
        player_id: u64::try_from(player_id)
            .map_err(|_| RepositoryError::Unavailable("negative player_id in accounts".into()))?,
        username: row.get("username"),
        password: row.get("password"),
        rank: row.get("rank"),
        gold: u32::try_from(gold)
            .map_err(|_| RepositoryError::Unavailable("negative gold balance in accounts".into()))?,
        cash: u32::try_from(cash)
            .map_err(|_| RepositoryError::Unavailable("negative cash balance in accounts".into()))?,
        tags: u32::try_from(tags)
            .map_err(|_| RepositoryError::Unavailable("negative tags value in accounts".into()))?,
        access: row.get("access_level"),
        online: row.get("online"),
        clan_id: u32::try_from(clan_id)
            .map_err(|_| RepositoryError::Unavailable("negative clan_id in accounts".into()))?,
        ban_object_id: u64::try_from(row.get::<_, i64>("ban_object_id"))
            .map_err(|_| RepositoryError::Unavailable("negative ban_object_id in accounts".into()))?,
        status: u32::try_from(status)
            .map_err(|_| RepositoryError::Unavailable("accounts.status is outside u32 range".into()))?,
    })
}

impl<B: AuthSessionBridge> AuthRepository for PgAuthRepository<B> {
    fn lookup_token(&self, client_token_base64: &str) -> Result<Option<Account>, RepositoryError> {
        let stored = pb_auth_security::stored_token(client_token_base64)
            .map_err(|e| RepositoryError::Unavailable(e.to_string()))?;
        let mut client = self.lock()?;
        let row = client
            .query_opt(ACCOUNT_BY_TOKEN_SQL, &[&stored, &client_token_base64])
            .map_err(db_error)?;
        let Some(row) = row else {
            return Ok(None);
        };

        let legacy_token: String = row.get("token");
        let account = account_from_row(&row)?;
        if legacy_token != stored {
            // Lazy migration mirrors db.accountByToken. The predicate avoids
            // overwriting a token that another request has already rotated.
            client
                .execute(
                    "UPDATE accounts SET token = $1 WHERE player_id = $2 AND token = $3",
                    &[&stored, &(account.player_id as i64), &legacy_token],
                )
                .map_err(db_error)?;
        }
        Ok(Some(account))
    }

    fn active_ban_for_player(&self, player_id: u64) -> Result<Option<(u64, i64)>, RepositoryError> {
        let mut client = self.lock()?;
        let row = client
            .query_opt(
                r#"
                SELECT object_id, (EXTRACT(EPOCH FROM expire_date) * 1000)::bigint AS expires_ms
                  FROM base_ban_history
                 WHERE (owner_id = $1 OR player_id = $1)
                   AND expire_date > NOW()
                   AND type <> 'MUTE'
                 ORDER BY object_id DESC
                 LIMIT 1
                "#,
                &[&(player_id as i64)],
            )
            .map_err(db_error)?;
        row.map(|r| {
            let object_id: i64 = r.get("object_id");
            let expires_ms: i64 = r.get("expires_ms");
            Ok((
                u64::try_from(object_id).map_err(|_| {
                    RepositoryError::Unavailable("negative ban object_id".into())
                })?,
                expires_ms,
            ))
        })
        .transpose()
    }

    fn is_permanently_banned(&self, account: &Account) -> Result<bool, RepositoryError> {
        if account.access == -1 {
            return Ok(true);
        }
        let mut client = self.lock()?;
        let row = client
            .query_one(
                r#"
                SELECT
                    EXISTS (SELECT 1 FROM base_auto_ban WHERE owner_id = $1)
                    OR EXISTS (
                        SELECT 1 FROM base_ban_history
                         WHERE owner_id = $1 AND type <> 'MUTE'
                    ) AS banned
                "#,
                &[&(account.player_id as i64)],
            )
            .map_err(db_error)?;
        Ok(row.get("banned"))
    }

    fn persist_ban_object_id(
        &self,
        player_id: u64,
        object_id: u64,
    ) -> Result<(), RepositoryError> {
        let mut client = self.lock()?;
        client
            .execute(
                "UPDATE accounts SET ban_object_id = $1 WHERE player_id = $2",
                &[&(object_id as i64), &(player_id as i64)],
            )
            .map_err(db_error)?;
        Ok(())
    }

    fn update_mac_address(&self, player_id: u64, mac: &str) -> Result<(), RepositoryError> {
        let mut client = self.lock()?;
        client
            .execute(
                "UPDATE accounts SET mac_address = $1::macaddr WHERE player_id = $2",
                &[&mac, &(player_id as i64)],
            )
            .map_err(db_error)?;
        Ok(())
    }

    fn ban_status(&self, mac_upper_hex: &str, ip: &str) -> Result<BanStatus, RepositoryError> {
        let mut client = self.lock()?;
        let rows = client
            .query(
                r#"
                SELECT type, value
                  FROM base_ban_history
                 WHERE value IN ($1, $2) AND expire_date > NOW()
                "#,
                &[&mac_upper_hex, &ip],
            )
            .map_err(db_error)?;
        let mut result = BanStatus {
            mac: false,
            ip: false,
        };
        for row in rows {
            let kind: String = row.get("type");
            let value: String = row.get("value");
            if kind == "MAC" && value == mac_upper_hex {
                result.mac = true;
            } else if kind == "IP4" && value == ip {
                result.ip = true;
            }
        }
        Ok(result)
    }

    fn account_ban_expiry(&self, object_id: u64) -> Result<Option<i64>, RepositoryError> {
        let mut client = self.lock()?;
        let row = client
            .query_opt(
                "SELECT (EXTRACT(EPOCH FROM expire_date) * 1000)::bigint AS expires_ms FROM base_ban_history WHERE object_id = $1",
                &[&(object_id as i64)],
            )
            .map_err(db_error)?;
        Ok(row.map(|r| r.get("expires_ms")))
    }

    fn handle_existing_login(&self, account: &Account) -> Result<(), RepositoryError> {
        self.sessions.handle_existing_login(account)
    }

    fn prepare_successful_login(&self, player_id: u64) -> Result<(), RepositoryError> {
        self.sessions.prepare_successful_login(player_id)
    }

    fn claim_login(&self, player_id: u64, mac: &str) -> Result<bool, RepositoryError> {
        // One UPDATE is the compare-and-set. Concurrent LOGIN attempts cannot
        // both transition the same account from offline to authenticated.
        let mut client = self.lock()?;
        let changed = client
            .execute(
                r#"
                UPDATE accounts
                   SET mac_address = $1::macaddr,
                       status = $2,
                       online = TRUE
                 WHERE player_id = $3 AND online = FALSE
                "#,
                &[&mac, &(i64::from(STATUS_AUTH)), &(player_id as i64)],
            )
            .map_err(db_error)?;
        Ok(changed == 1)
    }

    fn mint_enter_ticket(&self, player_id: u64) -> Result<String, RepositoryError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| RepositoryError::Unavailable(e.to_string()))?
            .as_secs();
        self.ticket_signer
            .mint(player_id, now)
            .map_err(|e| RepositoryError::Unavailable(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_status_constant_fits_postgres_bigint() {
        assert_eq!(i64::from(STATUS_AUTH), 4_278_190_079);
    }
}
