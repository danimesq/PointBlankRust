//! CONNECT_ACK session key material.
//!
//! The reference generates a 1360-bit RSA public modulus, then overwrites its
//! first four bytes with SessionId + 29890. RSA itself is not used to encrypt
//! the session: modulus[0..16] and modulus[16..32] become CMess keys.

use rand::{rngs::OsRng, Rng};
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use std::error::Error;
use std::fmt;

pub const AUTH_RSA_BITS: usize = 1360;
pub const AUTH_SECURITY_KEY: i32 = 29_890;
const MODULUS_BYTES: usize = AUTH_RSA_BITS / 8;
const SESSION_SEED_MAX_EXCLUSIVE: u32 = 0x7fff;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    pub modulus: Vec<u8>,
    pub exponent: Vec<u8>,
    pub server_key: [u8; 16],
    pub client_key: [u8; 16],
}

#[derive(Debug)]
pub enum SessionKeyError {
    InvalidSessionId(u32),
    Rsa(String),
    InvalidModulusLength(usize),
}

impl fmt::Display for SessionKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSessionId(id) => {
                write!(f, "session id {id} is outside the Auth seed range")
            }
            Self::Rsa(message) => write!(f, "RSA session key generation failed: {message}"),
            Self::InvalidModulusLength(length) => {
                write!(f, "expected a {MODULUS_BYTES}-byte modulus, got {length}")
            }
        }
    }
}
impl Error for SessionKeyError {}

/// Generate the public key material used by the original CONNECT_ACK path.
pub fn generate_session_keys(session_id: u32) -> Result<SessionKeys, SessionKeyError> {
    if session_id == 0 || session_id > SESSION_SEED_MAX_EXCLUSIVE {
        // The reference calls Random.Next(sessionId, 0x7fff). Equal bounds
        // return that bound; only values greater than 0x7fff are invalid.
        return Err(SessionKeyError::InvalidSessionId(session_id));
    }

    let private = RsaPrivateKey::new(&mut OsRng, AUTH_RSA_BITS)
        .map_err(|error| SessionKeyError::Rsa(error.to_string()))?;
    let public = RsaPublicKey::from(&private);
    let mut modulus = public.n().to_bytes_be();
    if modulus.len() > MODULUS_BYTES {
        return Err(SessionKeyError::InvalidModulusLength(modulus.len()));
    }
    if modulus.len() < MODULUS_BYTES {
        let mut padded = vec![0; MODULUS_BYTES - modulus.len()];
        padded.extend_from_slice(&modulus);
        modulus = padded;
    }

    let security_word = (session_id as i32).wrapping_add(AUTH_SECURITY_KEY);
    modulus[..4].copy_from_slice(&security_word.to_le_bytes());
    let exponent = public.e().to_bytes_be();

    let mut server_key = [0; 16];
    let mut client_key = [0; 16];
    server_key.copy_from_slice(&modulus[..16]);
    client_key.copy_from_slice(&modulus[16..32]);

    Ok(SessionKeys {
        modulus,
        exponent,
        server_key,
        client_key,
    })
}

/// Match AuthManager's Random.Next(sessionId, 0x7fff) seed range.
pub fn generate_session_seed(session_id: u32) -> Result<u16, SessionKeyError> {
    if session_id == 0 || session_id > SESSION_SEED_MAX_EXCLUSIVE {
        return Err(SessionKeyError::InvalidSessionId(session_id));
    }
    if session_id == SESSION_SEED_MAX_EXCLUSIVE {
        return Ok(SESSION_SEED_MAX_EXCLUSIVE as u16);
    }
    Ok(OsRng.gen_range(session_id..SESSION_SEED_MAX_EXCLUSIVE) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_session_ids_outside_the_reference_seed_range() {
        assert!(matches!(
            generate_session_seed(0),
            Err(SessionKeyError::InvalidSessionId(0))
        ));
        assert!(matches!(
            generate_session_seed(0x8000),
            Err(SessionKeyError::InvalidSessionId(0x8000))
        ));
        assert_eq!(generate_session_seed(0x7fff).unwrap(), 0x7fff);
    }

    #[test]
    fn seed_is_inside_the_exclusive_reference_range() {
        for _ in 0..128 {
            let seed = generate_session_seed(7).unwrap();
            assert!((7..0x7fff).contains(&u32::from(seed)));
        }
    }

    #[test]
    fn rsa_material_matches_connect_ack_dimensions() {
        let keys = generate_session_keys(7).unwrap();
        assert_eq!(keys.modulus.len(), 170);
        assert_eq!(keys.exponent, [1, 0, 1]);
        assert_eq!(&keys.server_key[..], &keys.modulus[..16]);
        assert_eq!(&keys.client_key[..], &keys.modulus[16..32]);
        assert_eq!(
            i32::from_le_bytes(keys.modulus[..4].try_into().unwrap()),
            7 + AUTH_SECURITY_KEY
        );
    }
}
