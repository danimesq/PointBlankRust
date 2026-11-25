//! Point Blank Match UDP (port 40009) protocol codecs.
//!
//! Ported from danimesq/point-blank-webport/src/net/matchUdp.ts.
//! The reference documents the server-side sources in Server.Match/MatchClient.cs,
//! Data/Utils/AllUtils.cs, Data/Utils/Udp121Cipher.cs and the packet classes.
//!
//! This module is transport-independent. It does not open a UDP socket, own a
//! match session, or choose an RNG. Callers provide the random bytes/numbers
//! used by the outgoing 121 cipher.

use crate::bitwise::{bitwise_decrypt, bitwise_encrypt, InvalidShift};
use crate::packet::{PacketError, PacketReader, PacketWriter};

use std::error::Error;
use std::fmt;

pub const UDP_PORT: u16 = 40_009;
pub const UDP_VERSION: [u16; 2] = [34_289, 1_733];

pub const OP_PVP: u8 = 3;
pub const OP_PVE: u8 = 4;
pub const OP_REGISTER: u8 = 65;
pub const OP_CONNECT: u8 = 66;
pub const OP_UNREGISTER: u8 = 67;
pub const OP_PING: u8 = 97;

pub const SUB_USER: u8 = 0;
pub const SUB_GRENADE: u8 = 1;
pub const SUB_DROPPED_WEAPON: u8 = 2;
pub const SUB_STAGE_INFO_CHARA: u8 = 8;

/// UdpGameEvent values used by the original Match server.
pub mod ev {
    pub const ANIMATION: u32 = 0x0000_0002;
    pub const USE_OBJECT: u32 = 0x0000_0004;
    pub const HP_SYNC: u32 = 0x0000_0008;
    pub const ACTION_FOR_OBJECT_SYNC: u32 = 0x0000_0010;
    pub const RADIO_CHAT: u32 = 0x0000_0020;
    pub const WEAPON_RECOIL: u32 = 0x0000_0080;
    pub const ACTION_STATE: u32 = 0x0000_0100;
    pub const GET_WEAPON_FOR_HOST: u32 = 0x0000_0200;
    pub const CHARA_FIRE_N_HIT_DATA: u32 = 0x0000_0400;
    pub const MISSION_DATA: u32 = 0x0000_0800;
    pub const HIT_DATA: u32 = 0x0002_0000;
    pub const SUICIDE: u32 = 0x0010_0000;
    pub const DROP_WEAPON: u32 = 0x0040_0000;
    pub const SOUND_POS_ROTATION: u32 = 0x0080_0000;
    pub const GET_WEAPON_FOR_CLIENT: u32 = 0x0100_0000;
    pub const FIRE_DATA: u32 = 0x0200_0000;
    pub const WEAPON_SYNC: u32 = 0x0400_0000;
    pub const POS_ROTATION: u32 = 0x0800_0000;
    pub const GRENADE_HIT: u32 = 0x1000_0000;
}

/// Errors returned by the Match protocol codecs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchProtocolError {
    Packet(PacketError),
    InvalidKeyLength { key1: usize, key2: usize },
    InvalidCiphertext,
    InvalidPadding,
    InvalidOpcode(u8),
    FrameTooLarge(usize),
    InvalidBitwiseShift(u8),
}

impl fmt::Display for MatchProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packet(error) => write!(f, "packet error: {error}"),
            Self::InvalidKeyLength { key1, key2 } => {
                write!(f, "UDP 121 keys must be non-empty (got {key1} and {key2} bytes)")
            }
            Self::InvalidCiphertext => f.write_str("invalid UDP 121 ciphertext"),
            Self::InvalidPadding => f.write_str("invalid UDP 121 padding"),
            Self::InvalidOpcode(opcode) => write!(f, "invalid Match UDP opcode {opcode}"),
            Self::FrameTooLarge(length) => write!(f, "Match UDP datagram too large: {length} bytes"),
            Self::InvalidBitwiseShift(shift) => write!(f, "invalid bitwise shift {shift}"),
        }
    }
}

impl Error for MatchProtocolError {}

impl From<PacketError> for MatchProtocolError {
    fn from(value: PacketError) -> Self {
        Self::Packet(value)
    }
}

impl From<InvalidShift> for MatchProtocolError {
    fn from(value: InvalidShift) -> Self {
        Self::InvalidBitwiseShift(value.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MatchHeader {
    pub opcode: u8,
    pub slot: u8,
    pub time: f32,
    pub round: u8,
    pub length: u16,
    pub respawn: u8,
    pub round_number: u8,
    pub account_id: u8,
    pub unk1: u8,
    pub unk2: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomKey {
    /// (server_id << 20) | (channel_id << 12) | room_id.
    pub unique_room_id: u32,
    /// (map_id << 20) | (rule << 12) | room_type.
    pub room_seed: u32,
}

/// Explicit randomness for the first three UDP 121 header bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Udp121Random {
    pub iv1: u8,
    pub iv2: u8,
    pub mix: u8,
}

impl Udp121Random {
    pub fn validate(self) -> Result<Self, MatchProtocolError> {
        if self.iv1 > 31 || self.iv2 > 31 {
            return Err(MatchProtocolError::InvalidCiphertext);
        }
        Ok(self)
    }
}

/// Convert IEEE-754 binary32 to the binary16 bit pattern used by SharpDX Half.
///
/// This intentionally mirrors the reference implementation's rounding and
/// overflow behavior instead of introducing a third-party half-float crate.
pub fn to_half(value: f32) -> u16 {
    let bits = value.to_bits();
    let sign = ((bits >> 16) & 0x8000) as u16;
    let mut exponent = ((bits >> 23) & 0xff) as i32 - 127 + 15;
    let mut mantissa = bits & 0x7f_ff_ff;

    if exponent <= 0 {
        if exponent < -10 {
            return sign;
        }
        mantissa = (mantissa | 0x80_00_00) >> (1 - exponent);
        return sign | (((mantissa + 0x1000) >> 13) as u16);
    }

    if exponent >= 31 {
        return sign | 0x7c00;
    }

    mantissa += 0x1000;
    if (mantissa & 0x80_00_00) != 0 {
        mantissa = 0;
        exponent += 1;
        if exponent >= 31 {
            return sign | 0x7c00;
        }
    }

    sign | ((exponent as u16) << 10) | ((mantissa >> 13) as u16)
}

/// Convert an IEEE-754 binary16 bit pattern to binary32.
pub fn from_half(value: u16) -> f32 {
    let sign = if (value & 0x8000) != 0 { -1.0 } else { 1.0 };
    let exponent = (value >> 10) & 0x1f;
    let mantissa = value & 0x03ff;

    if exponent == 0 {
        return sign * f32::from(mantissa) * 2.0_f32.powi(-24);
    }
    if exponent == 31 {
        return if mantissa != 0 {
            f32::NAN
        } else if sign < 0.0 {
            f32::NEG_INFINITY
        } else {
            f32::INFINITY
        };
    }

    sign * (1.0 + f32::from(mantissa) / 1024.0) * 2.0_f32.powi(i32::from(exponent) - 15)
}

fn tap(buffer: &[u8], bit_position: usize) -> Result<u8, MatchProtocolError> {
    if buffer.is_empty() {
        return Err(MatchProtocolError::InvalidKeyLength { key1: 0, key2: 0 });
    }

    let byte_index = (bit_position >> 3) % buffer.len();
    let bit_offset = bit_position & 7;
    if bit_offset == 0 {
        return Ok(buffer[byte_index]);
    }

    let low = (buffer[byte_index] & (0xff >> bit_offset)) << bit_offset;
    let high = buffer[(byte_index + 1) % buffer.len()] >> (8 - bit_offset);
    Ok(low | high)
}

fn validate_udp_keys(key1: &[u8], key2: &[u8]) -> Result<(), MatchProtocolError> {
    if key1.is_empty() || key2.is_empty() {
        return Err(MatchProtocolError::InvalidKeyLength {
            key1: key1.len(),
            key2: key2.len(),
        });
    }
    Ok(())
}

fn pad_length(plain_length: usize) -> u8 {
    ((2usize.wrapping_sub(plain_length)) & 7) as u8 + 2
}

/// Encrypt a client-to-server UDP 121 blob.
///
/// Wire layout: [iv1, iv2, mix, pad_len, encrypted payload, encrypted pad].
/// key1 is the four little-endian bytes of header time; key2 is the four
/// little-endian bytes of header unk2.
pub fn udp121_encrypt_c2s(
    plaintext: &[u8],
    key1: &[u8],
    key2: &[u8],
    random: Udp121Random,
) -> Result<Vec<u8>, MatchProtocolError> {
    validate_udp_keys(key1, key2)?;
    let random = random.validate()?;

    let pad_len = usize::from(pad_length(plaintext.len()));
    let mut k1 = key1.to_vec();
    let mut k2 = key2.to_vec();
    let index1 = (usize::from(random.mix & 0x0f) + usize::from(random.iv1)) & 0xff;
    let index2 = (usize::from(random.mix >> 4) + usize::from(random.iv2)) & 0xff;
    let mut feedback = 0u8;
    let mut jitter = 0usize;

    let mut output = Vec::with_capacity(4 + plaintext.len() + pad_len);
    output.extend_from_slice(&[random.iv1, random.iv2, random.mix, pad_len as u8]);

    for index in 0..plaintext.len() + pad_len {
        feedback ^= tap(&k1, index1.wrapping_add(jitter))?;
        feedback ^= tap(&k2, index2.wrapping_add(jitter))?;

        let plain_byte = if index < plaintext.len() {
            plaintext[index]
        } else {
            pad_len as u8
        };
        let cipher_byte = feedback ^ plain_byte;
        output.push(cipher_byte);

        jitter = jitter.wrapping_add(usize::from(feedback)).wrapping_add(8);
        for byte in (0..k1.len()).step_by(2) {
            k1[byte] ^= cipher_byte;
        }
        for byte in (1..k2.len()).step_by(2) {
            k2[byte] ^= cipher_byte;
        }
    }

    Ok(output)
}

/// Decrypt a client-to-server UDP 121 blob and validate its two pad bytes.
/// This inverse is useful for server-side tests and compatibility diagnostics.
pub fn udp121_decrypt_c2s(
    ciphertext: &[u8],
    key1: &[u8],
    key2: &[u8],
) -> Result<Vec<u8>, MatchProtocolError> {
    validate_udp_keys(key1, key2)?;
    if ciphertext.len() < 4 {
        return Err(MatchProtocolError::InvalidCiphertext);
    }

    let iv1 = ciphertext[0];
    let iv2 = ciphertext[1];
    let mix = ciphertext[2];
    let pad_len = usize::from(ciphertext[3]);
    if !(2..=9).contains(&pad_len) || ciphertext.len() < 4 + pad_len {
        return Err(MatchProtocolError::InvalidCiphertext);
    }

    let data_len = ciphertext.len() - 4 - pad_len;
    let mut k1 = key1.to_vec();
    let mut k2 = key2.to_vec();
    let index1 = (usize::from(mix & 0x0f) + usize::from(iv1)) & 0xff;
    let index2 = (usize::from(mix >> 4) + usize::from(iv2)) & 0xff;
    let mut feedback = 0u8;
    let mut jitter = 0usize;
    let mut plaintext = Vec::with_capacity(data_len);
    let mut decoded_pad = Vec::with_capacity(pad_len);

    for index in 0..data_len + pad_len {
        feedback ^= tap(&k1, index1.wrapping_add(jitter))?;
        feedback ^= tap(&k2, index2.wrapping_add(jitter))?;

        let cipher_byte = ciphertext[4 + index];
        let plain_byte = feedback ^ cipher_byte;
        if index < data_len {
            plaintext.push(plain_byte);
        } else {
            decoded_pad.push(plain_byte);
        }

        jitter = jitter.wrapping_add(usize::from(feedback)).wrapping_add(8);
        for byte in (0..k1.len()).step_by(2) {
            k1[byte] ^= cipher_byte;
        }
        for byte in (1..k2.len()).step_by(2) {
            k2[byte] ^= cipher_byte;
        }
    }

    if decoded_pad.len() < 2
        || decoded_pad[0] != pad_len as u8
        || decoded_pad[1] != pad_len as u8
    {
        return Err(MatchProtocolError::InvalidPadding);
    }

    Ok(plaintext)
}

/// Decrypt a server-to-client UDP 121 blob.
///
/// The server variant has a different initial-index derivation, feedback step,
/// and state update from the client-to-server variant.
pub fn udp121_decrypt_s2c(
    ciphertext: &[u8],
    key1: &[u8],
    key2: &[u8],
) -> Result<Vec<u8>, MatchProtocolError> {
    validate_udp_keys(key1, key2)?;
    if ciphertext.len() < 4 {
        return Err(MatchProtocolError::InvalidCiphertext);
    }

    let iv1 = ciphertext[0];
    let iv2 = ciphertext[1];
    let mix = ciphertext[2];
    let pad_len = usize::from(ciphertext[3]);
    let Some(data_len) = ciphertext.len().checked_sub(4 + pad_len) else {
        return Err(MatchProtocolError::InvalidCiphertext);
    };

    let mut k1 = key1.to_vec();
    let mut k2 = key2.to_vec();
    if k1.len() < 3 || k2.len() < 4 {
        return Err(MatchProtocolError::InvalidKeyLength {
            key1: k1.len(),
            key2: k2.len(),
        });
    }

    let index1 = (usize::from(iv1) + usize::from(mix >> 4)) & 0xff;
    let index2 = (usize::from(iv2) + usize::from(mix & 0x0f)) & 0xff;
    let mut feedback = 0u8;
    let mut jitter = 0usize;
    let mut output = Vec::with_capacity(data_len);

    for index in 0..data_len {
        feedback ^= tap(&k1, index1.wrapping_add(jitter))?;
        feedback ^= tap(&k2, index2.wrapping_add(jitter))?;

        let cipher_byte = ciphertext[4 + index];
        output.push(feedback ^ cipher_byte);

        jitter = jitter.wrapping_add(usize::from(feedback)).wrapping_add(14);
        k1[0] ^= cipher_byte;
        k1[2] ^= cipher_byte;
        k2[1] ^= cipher_byte;
        k2[3] ^= cipher_byte;
    }

    Ok(output)
}

fn write_header(writer: &mut PacketWriter, header: MatchHeader, length: u16) {
    writer
        .write_c(header.opcode)
        .write_c(header.slot)
        .write_t(header.time)
        .write_c(header.round)
        .write_h(length)
        .write_c(header.respawn)
        .write_c(header.round_number)
        .write_c(header.account_id)
        .write_c(header.unk1)
        .write_d(header.unk2);
}

/// Read the common 17-byte plaintext Match UDP header.
pub fn read_header(data: &[u8]) -> Result<MatchHeader, MatchProtocolError> {
    let mut reader = PacketReader::new(data);
    let header = MatchHeader {
        opcode: reader.read_c()?,
        slot: reader.read_c()?,
        time: reader.read_t()?,
        round: reader.read_c()?,
        length: reader.read_h()?,
        respawn: reader.read_c()?,
        round_number: reader.read_c()?,
        account_id: reader.read_c()?,
        unk1: reader.read_c()?,
        unk2: reader.read_d()?,
    };
    Ok(header)
}

/// Build the 38-byte 121 REGISTER/UNREGISTER handshake.
pub fn build_handshake(
    opcode: u8,
    slot: u8,
    account_id: u8,
    room: RoomKey,
    dedication_slot: u8,
) -> Result<Vec<u8>, MatchProtocolError> {
    if opcode != OP_REGISTER && opcode != OP_UNREGISTER {
        return Err(MatchProtocolError::InvalidOpcode(opcode));
    }

    let header = MatchHeader {
        opcode,
        slot,
        time: 0.0,
        round: 0,
        length: 38,
        respawn: 0,
        round_number: 0,
        account_id,
        unk1: 0,
        unk2: 0,
    };

    let mut writer = PacketWriter::with_capacity(38);
    write_header(&mut writer, header, 38);
    writer
        .write_d(0x3428_2e8c)
        .write_d(0x2b3c_3014)
        .write_d(0x0007_05e4)
        .write_d(room.unique_room_id)
        .write_d(room.room_seed)
        .write_c(dedication_slot);
    Ok(writer.into_bytes())
}

/// Build the 26-byte legacy PING datagram (17-byte header + rotated 9-byte room trailer).
pub fn build_ping(
    slot: u8,
    account_id: u8,
    room: RoomKey,
    time: f32,
) -> Result<Vec<u8>, MatchProtocolError> {
    let length = 26u16;
    let header = MatchHeader {
        opcode: OP_PING,
        slot,
        time,
        round: 0,
        length,
        respawn: 0,
        round_number: 0,
        account_id,
        unk1: 0,
        unk2: 0,
    };

    let mut trailer = PacketWriter::with_capacity(9);
    trailer
        .write_d(room.unique_room_id)
        .write_c(255)
        .write_d(room.room_seed);

    let shift = ((usize::from(length) % 6) + 1) as u8;
    let rotated = bitwise_encrypt(&trailer.into_bytes(), shift)?;

    let mut writer = PacketWriter::with_capacity(26);
    write_header(&mut writer, header, length);
    writer.write_b(&rotated);
    Ok(writer.into_bytes())
}

/// Build C->S PVP game data (opcode 3).
///
/// The random closure is called four times in this exact order: once for the
/// header unk2, then for iv1, iv2, and mix. This preserves the reference
/// client's deterministic vector behavior while letting the caller inject a
/// cryptographically suitable source in production.
pub fn build_game_data_with_rng<F>(
    slot: u8,
    time: f32,
    round: u8,
    respawn: u8,
    round_number: u8,
    account_id: u8,
    unk1: u8,
    actions: &[u8],
    room: RoomKey,
    mut random: F,
) -> Result<Vec<u8>, MatchProtocolError>
where
    F: FnMut() -> f64,
{
    let unk2 = (random().clamp(0.0, 0.999_999_999_999_999_9) * 4_294_967_296.0) as u32;
    let iv1 = (random().clamp(0.0, 0.999_999_999_999_999_9) * 32.0) as u8;
    let iv2 = (random().clamp(0.0, 0.999_999_999_999_999_9) * 32.0) as u8;
    let mix = (random().clamp(0.0, 0.999_999_999_999_999_9) * 256.0) as u8;

    let mut time_bytes = PacketWriter::with_capacity(4);
    time_bytes.write_t(time);
    let mut unk2_bytes = PacketWriter::with_capacity(4);
    unk2_bytes.write_d(unk2);

    let encrypted = udp121_encrypt_c2s(
        actions,
        &time_bytes.into_bytes(),
        &unk2_bytes.into_bytes(),
        Udp121Random { iv1, iv2, mix },
    )?;

    let mut trailer = PacketWriter::with_capacity(9);
    trailer
        .write_d(room.unique_room_id)
        .write_c(255)
        .write_d(room.room_seed);

    let mut region = encrypted;
    region.extend_from_slice(&trailer.into_bytes());

    let length = 25usize + region.len();
    if length > usize::from(u16::MAX) {
        return Err(MatchProtocolError::FrameTooLarge(length));
    }

    let header = MatchHeader {
        opcode: OP_PVP,
        slot,
        time,
        round,
        length: length as u16,
        respawn,
        round_number,
        account_id,
        unk1,
        unk2,
    };

    let mut writer = PacketWriter::with_capacity(length);
    write_header(&mut writer, header, length as u16);
    writer.write_d(0).write_d(0);

    let shift = ((length % 6) + 1) as u8;
    let rotated = bitwise_encrypt(&region, shift)?;
    writer.write_b(&rotated);
    Ok(writer.into_bytes())
}

/// Result of decoding a server-to-client game-data datagram.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedGameData {
    pub header: MatchHeader,
    pub actions: Vec<u8>,
}

/// Decode S->C opcode 4/132 BaseWriteCode payloads into the decrypted action stream.
pub fn decode_server_game_data(
    datagram: &[u8],
) -> Result<Option<DecodedGameData>, MatchProtocolError> {
    if datagram.len() < 25 {
        return Ok(None);
    }

    let header = read_header(datagram)?;
    let length = usize::from(header.length);
    if length < 25 || length > datagram.len() {
        return Ok(None);
    }

    let shift = ((length % 6) + 1) as u8;
    let region = bitwise_decrypt(&datagram[25..length], shift)?;
    let actions = udp121_decrypt_s2c(&region, &datagram[2..6], &datagram[13..17])?;

    Ok(Some(DecodedGameData { header, actions }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ActionState {
    pub action: u16,
    pub value: u8,
    pub weapon_flag: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct PosRot {
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub yaw: f64,
    pub pitch: f64,
    pub area: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct FireInfo {
    pub effect: u8,
    pub part: u8,
    pub index: u16,
    pub weapon_id: u32,
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct HitInfo {
    pub start: [f32; 3],
    pub end: [f32; 3],
    pub victim_slot: u16,
    pub damage: u16,
    pub part: u8,
    pub object_type: u8,
    pub weapon_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WeaponDropInfo {
    pub ammo: u16,
    pub extra: u16,
    pub reserve: u16,
    pub flags: u8,
    pub weapon_id: u32,
    pub accessory: u8,
    pub extensions: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RadioInfo {
    pub id: u8,
    pub area: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeathInfo {
    pub killer_slot: u8,
    pub death_type: u8,
    pub hit_part: u8,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GrenadeSyncInfo {
    pub state: u8,
    pub owner: u8,
    pub weapon_id: u32,
    pub accessory: u8,
    pub extensions: u8,
    pub pos: [f32; 3],
    pub vel: [f32; 3],
    pub boom_info: u16,
}

impl Default for GrenadeSyncInfo {
    fn default() -> Self {
        Self {
            state: 0,
            owner: 0,
            weapon_id: 0,
            accessory: 0,
            extensions: 0,
            pos: [0.0; 3],
            vel: [0.0; 3],
            boom_info: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct DroppedWeaponInfo {
    pub pos: [f32; 3],
    pub ammo: u16,
    pub extra: u16,
    pub reserve: u16,
    pub resting: bool,
    pub flags: u8,
    pub weapon_id: u32,
    pub owner: u8,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ActionOut {
    pub action_state: Option<ActionState>,
    pub pos_rot: Option<PosRot>,
    pub hp: Option<u16>,
    pub weapon: Option<(u32, u8, u8)>,
    pub fire: Option<FireInfo>,
    pub hits: Vec<HitInfo>,
    pub radio: Option<RadioInfo>,
    pub drop: Option<WeaponDropInfo>,
    pub pickup: Option<WeaponDropInfo>,
    pub grenades: Vec<(u16, GrenadeSyncInfo)>,
    pub dropped: Vec<(u16, DroppedWeaponInfo)>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ActionIn {
    pub slot: u16,
    pub sub: u8,
    pub flags: u32,
    pub action_state: Option<ActionState>,
    pub pos_rot: Option<PosRot>,
    pub sound_time: Option<f32>,
    pub weapon_id: Option<u32>,
    pub hp: Option<u16>,
    pub fire: Option<FireInfo>,
    pub hits: Vec<HitInfo>,
    pub death: Option<DeathInfo>,
    pub radio: Option<RadioInfo>,
    pub drop: Option<WeaponDropInfo>,
    pub pickup: Option<WeaponDropInfo>,
    pub grenade: Option<GrenadeSyncInfo>,
    pub dropped: Option<DroppedWeaponInfo>,
}

pub fn angle_to_u16(angle: f64) -> u16 {
    let tau = std::f64::consts::PI * 2.0;
    let normalized = (angle % tau + tau) % tau;
    (normalized / tau * 65_535.0).round() as u16
}

pub fn u16_to_angle(value: u16) -> f64 {
    (f64::from(value) / 65_535.0) * (std::f64::consts::PI * 2.0)
}

/// HitIndex bitfield: damage[21..31], part[11..16], victim slot[2..10], type[0..1].
pub fn make_hit_index(victim_slot: u16, damage: u16, part: u8, object_type: u8) -> u32 {
    (u32::from(damage & 0x07ff) << 21)
        | (u32::from(part & 0x3f) << 11)
        | (u32::from(victim_slot & 0x01ff) << 2)
        | u32::from(object_type & 0x03)
}

fn write_drop_info(writer: &mut PacketWriter, drop: WeaponDropInfo) {
    writer
        .write_h(drop.ammo)
        .write_h(drop.extra)
        .write_h(drop.reserve)
        .write_h(0)
        .write_h(0)
        .write_h(0)
        .write_c(drop.flags)
        .write_d(drop.weapon_id)
        .write_c(drop.accessory)
        .write_c(drop.extensions);
}

fn read_drop_info(reader: &mut PacketReader<'_>) -> Result<WeaponDropInfo, PacketError> {
    let ammo = reader.read_h()?;
    let extra = reader.read_h()?;
    let reserve = reader.read_h()?;
    reader.skip(6)?;
    let flags = reader.read_c()?;
    let weapon_id = reader.read_d()?;
    let accessory = reader.read_c()?;
    let extensions = reader.read_c()?;
    Ok(WeaponDropInfo {
        ammo,
        extra,
        reserve,
        flags,
        weapon_id,
        accessory,
        extensions,
    })
}

fn write_vec3(writer: &mut PacketWriter, value: [f32; 3]) {
    writer.write_t(value[0]).write_t(value[1]).write_t(value[2]);
}

fn read_vec3(reader: &mut PacketReader<'_>) -> Result<[f32; 3], PacketError> {
    Ok([reader.read_t()?, reader.read_t()?, reader.read_t()?])
}

/// Encode a User action record, preserving the reference event ordering.
pub fn encode_user_action(slot: u16, action: &ActionOut) -> Vec<u8> {
    let mut body = PacketWriter::with_capacity(64);
    let mut flags = 0u32;

    if let Some(state) = action.action_state {
        flags |= ev::ACTION_STATE;
        body.write_h(state.action)
            .write_c(state.value)
            .write_c(state.weapon_flag);
    }

    if let Some(position) = action.pos_rot {
        flags |= ev::POS_ROTATION;
        body.write_h(angle_to_u16(position.yaw))
            .write_h(angle_to_u16(position.pitch))
            .write_h(position.area)
            .write_h(to_half(position.z))
            .write_h(to_half(position.x))
            .write_h(to_half(position.y));
    }

    if let Some(radio) = action.radio {
        flags |= ev::RADIO_CHAT;
        body.write_c(radio.id).write_c(radio.area);
    }

    if let Some((weapon_id, accessory, extensions)) = action.weapon {
        if action.drop.is_none() && action.pickup.is_none() {
            flags |= ev::WEAPON_SYNC;
            body.write_d(weapon_id)
                .write_c(accessory)
                .write_c(extensions);
        }
    }

    if let Some(hp) = action.hp {
        flags |= ev::HP_SYNC;
        body.write_h(hp);
    }

    if let Some(drop) = action.drop {
        flags |= ev::DROP_WEAPON;
        write_drop_info(&mut body, drop);
    }

    if let Some(pickup) = action.pickup {
        flags |= ev::GET_WEAPON_FOR_CLIENT;
        write_drop_info(&mut body, pickup);
    }

    if let Some(fire) = action.fire {
        flags |= ev::FIRE_DATA;
        body.write_c(fire.effect)
            .write_c(fire.part)
            .write_h(fire.index)
            .write_d(fire.weapon_id)
            .write_c(0)
            .write_c(0)
            .write_h(to_half(fire.x))
            .write_h(to_half(fire.y))
            .write_h(to_half(fire.z));
    }

    if !action.hits.is_empty() {
        flags |= ev::HIT_DATA;
        body.write_c(action.hits.len().min(255) as u8);
        for hit in action.hits.iter().take(255) {
            write_vec3(&mut body, hit.start);
            write_vec3(&mut body, hit.end);
            // The reference webport writes the end point a second time in the
            // third vector slot. Keep this byte layout for compatibility.
            write_vec3(&mut body, hit.end);
            body.write_h(0)
                .write_h(hit.victim_slot)
                .write_d(make_hit_index(
                    hit.victim_slot,
                    hit.damage,
                    hit.part,
                    hit.object_type,
                ))
                .write_d(hit.weapon_id)
                .write_c(0)
                .write_c(0);
        }
    }

    let data = body.into_bytes();
    let record_length = 9 + data.len();
    let mut output = PacketWriter::with_capacity(record_length);
    output
        .write_h(record_length as u16)
        .write_h(slot)
        .write_c(SUB_USER)
        .write_d(flags)
        .write_b(&data);
    output.into_bytes()
}

/// Encode one SubHead.Grenade record (35 bytes).
pub fn encode_grenade(net_index: u16, grenade: GrenadeSyncInfo) -> Vec<u8> {
    let mut writer = PacketWriter::with_capacity(35);
    writer
        .write_h(35)
        .write_h(net_index)
        .write_c(SUB_GRENADE)
        .write_c(grenade.state)
        .write_c(grenade.owner)
        .write_c((net_index & 0x0f) as u8)
        .write_c(0)
        .write_h(grenade.boom_info)
        .write_d(grenade.weapon_id)
        .write_c(grenade.accessory)
        .write_c(grenade.extensions)
        .write_h(to_half(grenade.pos[0]))
        .write_h(to_half(grenade.pos[1]))
        .write_h(to_half(grenade.pos[2]))
        .write_d(grenade.vel[0].to_bits())
        .write_d(grenade.vel[1].to_bits())
        .write_d(grenade.vel[2].to_bits());
    writer.into_bytes()
}

/// Encode one SubHead.DroppedWeapon record (36 bytes).
pub fn encode_dropped(drop_index: u16, dropped: DroppedWeaponInfo) -> Vec<u8> {
    let mut writer = PacketWriter::with_capacity(36);
    writer
        .write_h(36)
        .write_h(drop_index)
        .write_c(SUB_DROPPED_WEAPON)
        .write_h(to_half(dropped.pos[0]))
        .write_h(to_half(dropped.pos[1]))
        .write_h(to_half(dropped.pos[2]))
        .write_h(dropped.ammo)
        .write_h(dropped.extra)
        .write_h(dropped.reserve)
        .write_h(if dropped.resting { 1 } else { 0 })
        .write_c(dropped.flags)
        .write_d(dropped.weapon_id)
        .write_c(dropped.owner)
        .zeros(11);
    writer.into_bytes()
}

/// Encode the User record followed by optional grenade and dropped-weapon records.
pub fn encode_actions(slot: u16, action: &ActionOut) -> Vec<u8> {
    let mut output = encode_user_action(slot, action);
    for (index, grenade) in &action.grenades {
        output.extend_from_slice(&encode_grenade(*index, *grenade));
    }
    for (index, dropped) in &action.dropped {
        output.extend_from_slice(&encode_dropped(*index, *dropped));
    }
    output
}

fn read_grenade(reader: &mut PacketReader<'_>) -> Result<GrenadeSyncInfo, PacketError> {
    let state = reader.read_c()?;
    let owner = reader.read_c()?;
    reader.skip(2)?;
    let boom_info = reader.read_h()?;
    let weapon_id = reader.read_d()?;
    let accessory = reader.read_c()?;
    let extensions = reader.read_c()?;
    let pos = [
        from_half(reader.read_h()?),
        from_half(reader.read_h()?),
        from_half(reader.read_h()?),
    ];
    let vel = [
        f32::from_bits(reader.read_d()?),
        f32::from_bits(reader.read_d()?),
        f32::from_bits(reader.read_d()?),
    ];
    Ok(GrenadeSyncInfo {
        state,
        owner,
        weapon_id,
        accessory,
        extensions,
        pos,
        vel,
        boom_info,
    })
}

fn read_dropped(reader: &mut PacketReader<'_>) -> Result<DroppedWeaponInfo, PacketError> {
    let pos = [
        from_half(reader.read_h()?),
        from_half(reader.read_h()?),
        from_half(reader.read_h()?),
    ];
    let ammo = reader.read_h()?;
    let extra = reader.read_h()?;
    let reserve = reader.read_h()?;
    let resting = reader.read_h()? == 1;
    let flags = reader.read_c()?;
    let weapon_id = reader.read_d()?;
    let owner = reader.read_c()?;
    Ok(DroppedWeaponInfo {
        pos,
        ammo,
        extra,
        reserve,
        resting,
        flags,
        weapon_id,
        owner,
    })
}

fn decode_events(
    reader: &mut PacketReader<'_>,
    flags: u32,
    action: &mut ActionIn,
) -> Result<(), PacketError> {
    let has = |flag| (flags & flag) != 0;

    // Server death event (PROTOCOL_EVENTS_ACTION type 2).
    if flags == (ev::HP_SYNC | ev::GET_WEAPON_FOR_HOST) || flags == ev::HP_SYNC {
        action.hp = Some(reader.read_h()?);
        if has(ev::GET_WEAPON_FOR_HOST) {
            let death_type = reader.read_c()?;
            let killer_slot = reader.read_c()?;
            reader.skip(10)?;
            let hit_part = reader.read_c()?;
            action.death = Some(DeathInfo {
                killer_slot,
                death_type,
                hit_part,
            });
        }
        return Ok(());
    }

    if has(ev::ACTION_STATE) {
        action.action_state = Some(ActionState {
            action: reader.read_h()?,
            value: reader.read_c()?,
            weapon_flag: reader.read_c()?,
        });
    }
    if has(ev::ANIMATION) {
        reader.skip(8)?;
    }
    if has(ev::POS_ROTATION) {
        let yaw = u16_to_angle(reader.read_h()?);
        let pitch_angle = u16_to_angle(reader.read_h()?);
        let area = reader.read_h()?;
        let z = from_half(reader.read_h()?);
        let x = from_half(reader.read_h()?);
        let y = from_half(reader.read_h()?);
        let pitch = if pitch_angle > std::f64::consts::PI {
            pitch_angle - std::f64::consts::PI * 2.0
        } else {
            pitch_angle
        };
        action.pos_rot = Some(PosRot {
            x,
            y,
            z,
            yaw,
            pitch,
            area,
        });
    }
    if has(ev::SOUND_POS_ROTATION) {
        action.sound_time = Some(reader.read_t()?);
    }
    if has(ev::USE_OBJECT) {
        let count = usize::from(reader.read_c()?);
        reader.skip(count.saturating_mul(4))?;
    }
    if has(ev::ACTION_FOR_OBJECT_SYNC) {
        reader.skip(2)?;
    }
    if has(ev::RADIO_CHAT) {
        action.radio = Some(RadioInfo {
            id: reader.read_c()?,
            area: reader.read_c()?,
        });
    }
    if has(ev::WEAPON_SYNC) {
        action.weapon_id = Some(reader.read_d()?);
        reader.skip(2)?;
    }
    if has(ev::WEAPON_RECOIL) {
        reader.skip(27)?;
    }
    if has(ev::HP_SYNC) {
        action.hp = Some(reader.read_h()?);
    }
    if has(ev::SUICIDE) {
        let count = usize::from(reader.read_c()?);
        reader.skip(count.saturating_mul(16))?;
    }
    if has(ev::MISSION_DATA) {
        return Ok(());
    }
    if has(ev::DROP_WEAPON) {
        action.drop = Some(read_drop_info(reader)?);
    }
    if has(ev::GET_WEAPON_FOR_CLIENT) {
        action.pickup = Some(read_drop_info(reader)?);
    }
    if has(ev::FIRE_DATA) {
        let effect = reader.read_c()?;
        let part = reader.read_c()?;
        let index = reader.read_h()?;
        let weapon_id = reader.read_d()?;
        reader.skip(2)?;
        action.fire = Some(FireInfo {
            effect,
            part,
            index,
            weapon_id,
            x: from_half(reader.read_h()?),
            y: from_half(reader.read_h()?),
            z: from_half(reader.read_h()?),
        });
    }
    if has(ev::CHARA_FIRE_N_HIT_DATA) {
        return Ok(());
    }
    if has(ev::HIT_DATA) {
        let count = usize::from(reader.read_c()?);
        action.hits.reserve(count);
        for _ in 0..count {
            let start = read_vec3(reader)?;
            let end = read_vec3(reader)?;
            let _third_position = read_vec3(reader)?;
            reader.read_h()?;
            let victim_slot = reader.read_h()?;
            let hit_index = reader.read_d()?;
            let weapon_id = reader.read_d()?;
            reader.skip(2)?;
            action.hits.push(HitInfo {
                start,
                end,
                victim_slot,
                damage: ((hit_index >> 21) & 0x07ff) as u16,
                part: ((hit_index >> 11) & 0x3f) as u8,
                object_type: (hit_index & 0x03) as u8,
                weapon_id,
            });
        }
    }

    Ok(())
}

/// Parse an S->C action stream. Unknown sub-record types are skipped by length.
/// Malformed records return a bounded packet error instead of panicking.
pub fn decode_actions(stream: &[u8]) -> Result<Vec<ActionIn>, PacketError> {
    let mut output = Vec::new();
    let mut reader = PacketReader::new(stream);

    while reader.remaining() >= 5 {
        let record_start = reader.position();
        let length = usize::from(reader.read_h()?);
        let slot = reader.read_h()?;
        let sub = reader.read_c()?;

        if sub == 0xff || length < 5 {
            break;
        }

        let Some(record_end) = record_start.checked_add(length) else {
            break;
        };
        if record_end > stream.len() {
            break;
        }

        let body_start = reader.position();
        match sub {
            SUB_USER | SUB_STAGE_INFO_CHARA if length >= 9 => {
                let mut body = PacketReader::with_offset(stream, body_start)?;
                let flags = body.read_d()?;
                let mut action = ActionIn {
                    slot,
                    sub,
                    flags,
                    ..ActionIn::default()
                };
                decode_events(&mut body, flags, &mut action)?;
                output.push(action);
            }
            SUB_GRENADE if length >= 35 => {
                let mut body = PacketReader::with_offset(stream, body_start)?;
                output.push(ActionIn {
                    slot,
                    sub,
                    grenade: Some(read_grenade(&mut body)?),
                    ..ActionIn::default()
                });
            }
            SUB_DROPPED_WEAPON if length >= 36 => {
                let mut body = PacketReader::with_offset(stream, body_start)?;
                output.push(ActionIn {
                    slot,
                    sub,
                    dropped: Some(read_dropped(&mut body)?),
                    ..ActionIn::default()
                });
            }
            _ => {}
        }

        reader = PacketReader::with_offset(stream, record_end)?;
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn half_float_reference_values() {
        let vectors = [
            (0.0, 0x0000),
            (1.0, 0x3c00),
            (-1.0, 0xbc00),
            (0.5, 0x3800),
            (12.5, 0x4a40),
            (-30.25, 0xcf90),
            (100.0, 0x5640),
        ];

        for (value, expected) in vectors {
            assert_eq!(to_half(value), expected);
            assert!((from_half(expected) - value).abs() <= value.abs() / 1024.0 + 0.0001);
        }
    }

    #[test]
    fn udp121_c2s_round_trip_checks_padding() {
        let plain = [0x02, 0x09, 1, 2, 3, 4, 5];
        let key1 = [0x00, 0x00, 0xa8, 0x40];
        let key2 = [0x01, 0x02, 0x03, 0x04];
        let random = Udp121Random {
            iv1: 17,
            iv2: 9,
            mix: 0xc4,
        };
        let encrypted = udp121_encrypt_c2s(&plain, &key1, &key2, random).unwrap();
        assert_eq!(udp121_decrypt_c2s(&encrypted, &key1, &key2).unwrap(), plain);
    }

    #[test]
    fn udp121_rejects_empty_keys_and_truncated_ciphertext() {
        assert!(matches!(
            udp121_encrypt_c2s(
                &[1],
                &[],
                &[1, 2, 3, 4],
                Udp121Random {
                    iv1: 0,
                    iv2: 0,
                    mix: 0
                }
            ),
            Err(MatchProtocolError::InvalidKeyLength { .. })
        ));
        assert_eq!(
            udp121_decrypt_c2s(&[1, 2, 3], &[1], &[1]),
            Err(MatchProtocolError::InvalidCiphertext)
        );
    }
}
