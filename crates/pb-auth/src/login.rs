//! LOGIN (1281) request decoding.
//!
//! The decoder mirrors the reference server's PROTOCOL_BASE_LOGIN_REQ.Read()
//! field order. It deliberately performs no account lookup or policy decision:
//! those belong to the Auth service layer.

use base64::Engine as _;

/// Maximum variable-length LOGIN fields accepted by the protocol decoder.
const MAX_LOGIN_FIELD_LEN: usize = 4096;

/// Decoded fields from a client LOGIN request (opcode 1281).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginRequest {
    /// Hardware fingerprint component used by the reference ValidateKey.
    pub hw_spec0: u32,
    pub mac: [u8; 6],
    pub resolution: (u16, u16),
    pub user_file_list: String,
    pub locale: u8,
    pub client_version: (u8, u8),
    /// The reference server converts the opaque token bytes to standard Base64
    /// before looking up accounts.token.
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginDecodeError {
    Truncated {
        field: &'static str,
        needed: usize,
        remaining: usize,
    },
    FieldTooLarge {
        field: &'static str,
        length: usize,
        maximum: usize,
    },
    InvalidUtf8 {
        field: &'static str,
    },
}

impl std::fmt::Display for LoginDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated {
                field,
                needed,
                remaining,
            } => write!(
                f,
                "truncated LOGIN {field}: need {needed} bytes, have {remaining}"
            ),
            Self::FieldTooLarge {
                field,
                length,
                maximum,
            } => write!(f, "LOGIN {field} length {length} exceeds maximum {maximum}"),
            Self::InvalidUtf8 { field } => write!(f, "LOGIN {field} is not valid UTF-8"),
        }
    }
}
impl std::error::Error for LoginDecodeError {}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, field: &'static str, length: usize) -> Result<&'a [u8], LoginDecodeError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if length > remaining {
            return Err(LoginDecodeError::Truncated {
                field,
                needed: length,
                remaining,
            });
        }
        let start = self.offset;
        self.offset += length;
        Ok(&self.bytes[start..self.offset])
    }

    fn skip(&mut self, field: &'static str, length: usize) -> Result<(), LoginDecodeError> {
        self.take(field, length).map(|_| ())
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, LoginDecodeError> {
        Ok(self.take(field, 1)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, LoginDecodeError> {
        let bytes = self.take(field, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn bounded_len(&mut self, field: &'static str) -> Result<usize, LoginDecodeError> {
        let length = usize::from(self.u16(field)?);
        if length > MAX_LOGIN_FIELD_LEN {
            return Err(LoginDecodeError::FieldTooLarge {
                field,
                length,
                maximum: MAX_LOGIN_FIELD_LEN,
            });
        }
        Ok(length)
    }
}

impl LoginRequest {
    /// Decode the LOGIN body after the 4-byte [opcode, session-seed] header.
    ///
    /// The hardware value intentionally reads body bytes 1..5, matching the
    /// reference implementation's overlapping legacy field extraction.
    pub fn decode(body: &[u8]) -> Result<Self, LoginDecodeError> {
        let hw = body.get(1..5).ok_or(LoginDecodeError::Truncated {
            field: "hardware fingerprint",
            needed: 4,
            remaining: body.len().saturating_sub(1),
        })?;
        let hw_spec0 = u32::from_le_bytes([hw[0], hw[1], hw[2], hw[3]]);
        let mut cursor = Cursor::new(body);

        cursor.skip("header fields", 4)?;
        let mac: [u8; 6] = cursor
            .take("MAC address", 6)?
            .try_into()
            .expect("six-byte slice");
        cursor.skip("reserved fields before resolution", 21)?;
        let resolution = (
            cursor.u16("resolution width")?,
            cursor.u16("resolution height")?,
        );
        cursor.skip("reserved fields before user file list", 10)?;
        let list_len = usize::from(cursor.u8("user file list length")?);
        if list_len > MAX_LOGIN_FIELD_LEN {
            return Err(LoginDecodeError::FieldTooLarge {
                field: "user file list",
                length: list_len,
                maximum: MAX_LOGIN_FIELD_LEN,
            });
        }
        let list = cursor.take("user file list", list_len)?;
        let user_file_list = std::str::from_utf8(list)
            .map_err(|_| LoginDecodeError::InvalidUtf8 {
                field: "user file list",
            })?
            .to_owned();
        cursor.skip("reserved fields before locale", 16)?;
        let locale = cursor.u8("locale")?;
        let client_version = (
            cursor.u8("client version major")?,
            cursor.u8("client version minor")?,
        );
        cursor.skip("reserved field before token", 1)?;
        let token_len = cursor.bounded_len("token length")?;
        let token_bytes = cursor.take("token", token_len)?;
        let token = base64::engine::general_purpose::STANDARD.encode(token_bytes);

        Ok(Self {
            hw_spec0,
            mac,
            resolution,
            user_file_list,
            locale,
            client_version,
            token,
        })
    }

    pub fn resolution_string(&self) -> String {
        format!("{}x{}", self.resolution.0, self.resolution.1)
    }

    pub fn client_version_string(&self) -> String {
        format!("{}.{}", self.client_version.0, self.client_version.1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_body() -> Vec<u8> {
        let mut body = vec![0x11, 0x57, 0x45, 0x42]; // hardware extraction is bytes 1..5
        body.extend_from_slice(&[0xaa, 0xbb]); // remaining bytes of the 6-byte MAC
        body.extend_from_slice(&[0; 21]);
        body.extend_from_slice(&1920u16.to_le_bytes());
        body.extend_from_slice(&1080u16.to_le_bytes());
        body.extend_from_slice(&[0; 10]);
        body.push(4);
        body.extend_from_slice(b"ABCD");
        body.extend_from_slice(&[0; 16]);
        body.push(1); // locale
        body.extend_from_slice(&[5, 42]); // version 5.42
        body.push(0);
        body.extend_from_slice(&3u16.to_le_bytes());
        body.extend_from_slice(b"xyz");
        body
    }

    #[test]
    fn decodes_reference_login_field_order_and_token_encoding() {
        let req = LoginRequest::decode(&request_body()).unwrap();
        assert_eq!(
            req.hw_spec0,
            u32::from_le_bytes([0x57, 0x45, 0x42, 0xaa])
        );
        assert_eq!(req.mac, [0x11, 0x57, 0x45, 0x42, 0xaa, 0xbb]);
        assert_eq!(req.resolution, (1920, 1080));
        assert_eq!(req.resolution_string(), "1920x1080");
        assert_eq!(req.user_file_list, "ABCD");
        assert_eq!(req.locale, 1);
        assert_eq!(req.client_version_string(), "5.42");
        assert_eq!(req.token, "eHl6");
    }

    #[test]
    fn rejects_truncated_and_oversized_token_fields() {
        let mut body = request_body();
        body.pop();
        assert!(matches!(
            LoginRequest::decode(&body),
            Err(LoginDecodeError::Truncated { field: "token", .. })
        ));

        let mut body = request_body();
        let len_at = body.len() - 5;
        body[len_at..len_at + 2].copy_from_slice(&4097u16.to_le_bytes());
        assert!(matches!(
            LoginRequest::decode(&body),
            Err(LoginDecodeError::FieldTooLarge {
                field: "token length",
                ..
            })
        ));
    }

    #[test]
    fn rejects_invalid_user_file_list_utf8() {
        let mut body = request_body();
        let list_at = 4 + 6 + 21 + 4 + 10 + 1;
        body[list_at] = 0xff;
        assert!(matches!(
            LoginRequest::decode(&body),
            Err(LoginDecodeError::InvalidUtf8 {
                field: "user file list"
            })
        ));
    }
}
