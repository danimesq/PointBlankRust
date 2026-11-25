//! Cryptographic primitives shared by Point Blank Auth and Game services.
//!
//! These formats intentionally match point-blank-webport:
//! - stored account token: "h:" + first 30 base64url chars of SHA-256(token)
//! - enter ticket: base64url("enter.<player_id>.<expiry_unix_seconds>") + "." +
//!   base64url(HMAC-SHA256(secret, encoded_body))
//!
//! The application must supply the same 32-byte ticket secret to Auth and Game.
//! Never generate an independent secret in each service process.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

const STORED_TOKEN_PREFIX: &str = "h:";
const STORED_TOKEN_DIGEST_CHARS: usize = 30;
const ENTER_TICKET_TTL_SECS: u64 = 12 * 60 * 60;
const MAX_TICKET_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    EmptyToken,
    StoredTokenIsNotCredential,
    InvalidSecretLength,
    InvalidTicket,
    ExpiredTicket,
    ExpiryOverflow,
}
impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyToken => "client token cannot be empty",
            Self::StoredTokenIsNotCredential => "stored token hashes are not client credentials",
            Self::InvalidSecretLength => "enter-ticket secret must contain exactly 32 bytes",
            Self::InvalidTicket => "invalid enter ticket",
            Self::ExpiredTicket => "enter ticket has expired",
            Self::ExpiryOverflow => "enter-ticket expiry overflow",
        })
    }
}
impl std::error::Error for SecurityError {}

/// Match WebPort's storedToken(): h: + 30 chars of base64url(SHA-256(token)).
pub fn stored_token(client_token: &str) -> Result<String, SecurityError> {
    if client_token.is_empty() {
        return Err(SecurityError::EmptyToken);
    }
    if is_stored_token(client_token) {
        return Err(SecurityError::StoredTokenIsNotCredential);
    }
    let digest = Sha256::digest(client_token.as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(digest);
    Ok(format!(
        "{STORED_TOKEN_PREFIX}{}",
        &encoded[..STORED_TOKEN_DIGEST_CHARS]
    ))
}

/// Stored hashes must never be accepted as bearer credentials.
pub fn is_stored_token(value: &str) -> bool {
    value.starts_with(STORED_TOKEN_PREFIX)
}

/// Signs and verifies WebPort-compatible enter tickets.
#[derive(Clone)]
pub struct EnterTicketSigner {
    secret: [u8; 32],
}
impl EnterTicketSigner {
    /// The caller must load one shared secret and pass the same bytes to Auth and Game.
    pub fn new(secret: &[u8]) -> Result<Self, SecurityError> {
        let secret: [u8; 32] = secret
            .try_into()
            .map_err(|_| SecurityError::InvalidSecretLength)?;
        Ok(Self { secret })
    }

    /// Mint an enter ticket valid for 12 hours, matching WebPort's default TTL.
    pub fn mint(&self, player_id: u64, now_unix_secs: u64) -> Result<String, SecurityError> {
        let expiry = now_unix_secs
            .checked_add(ENTER_TICKET_TTL_SECS)
            .ok_or(SecurityError::ExpiryOverflow)?;
        self.mint_until(player_id, expiry)
    }

    /// Mint with an explicit expiry, useful for controlled deployments and tests.
    pub fn mint_until(
        &self,
        player_id: u64,
        expiry_unix_secs: u64,
    ) -> Result<String, SecurityError> {
        let claims = format!("enter.{player_id}.{expiry_unix_secs}");
        let body = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts keys of any length");
        mac.update(body.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        Ok(format!("{body}.{signature}"))
    }

    /// Return the player ID only when the MAC is valid and the ticket has not expired.
    pub fn verify(&self, ticket: &str, now_unix_secs: u64) -> Result<u64, SecurityError> {
        if ticket.len() > MAX_TICKET_LEN {
            return Err(SecurityError::InvalidTicket);
        }
        let (body, signature) = ticket.split_once('.').ok_or(SecurityError::InvalidTicket)?;
        if body.is_empty() || signature.is_empty() || signature.contains('.') {
            return Err(SecurityError::InvalidTicket);
        }

        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| SecurityError::InvalidTicket)?;
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .expect("HMAC accepts keys of any length");
        mac.update(body.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| SecurityError::InvalidTicket)?;

        let decoded = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| SecurityError::InvalidTicket)?;
        let claims = std::str::from_utf8(&decoded).map_err(|_| SecurityError::InvalidTicket)?;
        let mut parts = claims.split('.');
        if parts.next() != Some("enter") {
            return Err(SecurityError::InvalidTicket);
        }
        let player_id = parts
            .next()
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or(SecurityError::InvalidTicket)?;
        let expiry = parts
            .next()
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or(SecurityError::InvalidTicket)?;
        if parts.next().is_some() {
            return Err(SecurityError::InvalidTicket);
        }
        if expiry <= now_unix_secs {
            return Err(SecurityError::ExpiredTicket);
        }
        Ok(player_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_token_matches_webport_format() {
        assert_eq!(
            stored_token("dG9rZW4=").unwrap(),
            "h:SvL9MY6l1lC-esTN2nFNADHoRjX7j3"
        );
    }

    #[test]
    fn stored_hash_cannot_be_used_as_a_credential() {
        let hash = stored_token("client-token").unwrap();
        assert!(is_stored_token(&hash));
        assert_eq!(
            stored_token(&hash),
            Err(SecurityError::StoredTokenIsNotCredential)
        );
    }

    #[test]
    fn enter_ticket_round_trips_and_expires() {
        let signer = EnterTicketSigner::new(&[7; 32]).unwrap();
        let ticket = signer.mint(126, 1_800_000_000).unwrap();
        assert_eq!(signer.verify(&ticket, 1_800_000_001), Ok(126));
        assert_eq!(
            signer.verify(&ticket, 1_800_000_000 + ENTER_TICKET_TTL_SECS),
            Err(SecurityError::ExpiredTicket)
        );
    }

    #[test]
    fn enter_ticket_rejects_tampering_and_wrong_secret() {
        let signer = EnterTicketSigner::new(&[7; 32]).unwrap();
        let other = EnterTicketSigner::new(&[8; 32]).unwrap();
        let ticket = signer.mint(126, 1_800_000_000).unwrap();
        assert_eq!(
            other.verify(&ticket, 1_800_000_001),
            Err(SecurityError::InvalidTicket)
        );
        let tampered = ticket.replacen('.', "x", 1);
        assert_eq!(
            signer.verify(&tampered, 1_800_000_001),
            Err(SecurityError::InvalidTicket)
        );
    }

    #[test]
    fn signer_requires_exactly_32_secret_bytes() {
        assert_eq!(
            EnterTicketSigner::new(&[1; 31]).err(),
            Some(SecurityError::InvalidSecretLength)
        );
    }
}
