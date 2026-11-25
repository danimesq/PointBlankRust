//! C#-derived Match UDP vectors from point-blank-webport/src/net/test/match-vectors.json.
//! The same fixture validates datagram framing, 121 encryption, half-float layout,
//! and the byte-exact User action encoder.

use pb_protocol::match_udp::{
    build_game_data_with_rng, build_handshake, decode_actions, decode_server_game_data,
    encode_user_action, from_half, to_half, ActionOut, HitInfo, MatchProtocolError, PosRot,
    RoomKey, UDP_VERSION, OP_REGISTER,
};

fn from_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("hex is ASCII");
            u8::from_str_radix(pair, 16).expect("valid hex")
        })
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

const ACTIONS: &str = "4a0003000008000208e430c6f3000090cf404a003f6400010000803f0000004000004040000080400000a0400000c040000080400000a0400000c0400000020009702004b9ecf5050000";
const C2S_DATAGRAM: &str = "03030000a84000720001002a00a67ec64100000000000000002424b404d4a75d74cd1baa45e996bf31b4d569365f206dbef4a0e72a767ee28a7104860a7940f990a3ac771aea6a232c2f53ba8d50dce0d7ce13c89a2b0d6ea3bc34431b1b536682cf1a10f181e8cbbc0a202001fe08208004";
const S2C_DATAGRAM: &str = "04ff0000484100690001000700e10397450000000000000000a0140029a2d650d649bcdcbadb284f93430157f90149463bd45ae82ff641eafdc3d41ca9c33ae939825306402c571336588ae922c09a25be1ff3e0492610bd840bcb8663717b4d18102b698e04a7fbf0";
const ROOM: RoomKey = RoomKey {
    unique_room_id: 0x0010_1005,
    room_seed: 0x0240_1004,
};

fn reference_rng() -> impl FnMut() -> f64 {
    // Match the JavaScript test's Number multiplication and >>> 0 conversion.
    let mut seed = 1u32;
    move || {
        let next = (f64::from(seed) * 1_103_515_245.0 + 12_345.0) % 4_294_967_296.0;
        seed = next as u32;
        f64::from(seed) / 4_294_967_296.0
    }
}

#[test]
fn user_action_encoding_matches_reference_bytes() {
    let action = ActionOut {
        pos_rot: Some(PosRot {
            x: 12.5,
            y: 1.75,
            z: -30.25,
            yaw: 1.2,
            pitch: -0.3,
            area: 0,
        }),
        hp: Some(100),
        hits: vec![HitInfo {
            start: [1.0, 2.0, 3.0],
            end: [4.0, 5.0, 6.0],
            victim_slot: 2,
            damage: 33,
            part: 14,
            object_type: 1,
            weapon_id: 100_003_001,
        }],
        ..ActionOut::default()
    };

    assert_eq!(to_hex(&encode_user_action(3, &action)), ACTIONS);
}

#[test]
fn c2s_pvp_datagram_matches_reference_and_preserves_header() {
    let datagram = build_game_data_with_rng(
        3,
        5.25,
        0,
        1,
        0,
        42,
        0,
        &from_hex(ACTIONS),
        ROOM,
        reference_rng(),
    )
    .unwrap();

    assert_eq!(to_hex(&datagram), C2S_DATAGRAM);
    let header = pb_protocol::match_udp::read_header(&datagram).unwrap();
    assert_eq!(header.opcode, 3);
    assert_eq!(header.slot, 3);
    assert_eq!(header.length as usize, datagram.len());
    assert_eq!(header.unk2, 0x41c6_7ea6);
}

#[test]
fn s2c_datagram_matches_reference_and_decodes_actions() {
    let datagram = from_hex(S2C_DATAGRAM);
    let decoded = decode_server_game_data(&datagram).unwrap().unwrap();

    assert_eq!(decoded.header.opcode, 4);
    assert_eq!(to_hex(&decoded.actions), ACTIONS);

    let actions = decode_actions(&decoded.actions).unwrap();
    let action = &actions[0];
    assert_eq!(action.slot, 3);
    assert_eq!(action.hp, Some(100));
    let position = action.pos_rot.unwrap();
    assert_eq!([position.x, position.y, position.z], [12.5, 1.75, -30.25]);
    let hit = action.hits[0];
    assert_eq!(hit.victim_slot, 2);
    assert_eq!(hit.damage, 33);
    assert_eq!(hit.part, 14);
    assert_eq!(hit.object_type, 1);
}

#[test]
fn register_handshake_matches_reference_layout() {
    let handshake = build_handshake(OP_REGISTER, 1, 7, ROOM, 255).unwrap();
    assert_eq!(handshake.len(), 38);
    assert_eq!(u16::from_le_bytes([handshake[7], handshake[8]]), 38);
    assert_eq!(
        to_hex(&handshake[17..]),
        "8c2e283414303c2be40507000510100004104002ff"
    );
    assert_eq!(UDP_VERSION, [34_289, 1_733]);
}

#[test]
fn half_float_codec_covers_finite_values_and_special_values() {
    for value in [0.0, 1.0, -1.0, 0.5, 12.5, -30.25, 100.0, 1000.5] {
        let half = to_half(value);
        assert!((from_half(half) - value).abs() <= value.abs() / 1024.0 + 0.0001);
    }

    assert_eq!(to_half(f32::INFINITY), 0x7c00);
    assert_eq!(to_half(f32::NEG_INFINITY), 0xfc00);
    assert!(from_half(0x7e00).is_nan());
}

#[test]
fn malformed_server_datagrams_are_rejected_without_panics() {
    assert!(decode_server_game_data(&[0; 24]).unwrap().is_none());
    let mut truncated = from_hex(S2C_DATAGRAM);
    truncated[7] = 0xff;
    truncated[8] = 0x7f;
    assert!(decode_server_game_data(&truncated).unwrap().is_none());
    assert_eq!(
        build_handshake(3, 1, 7, ROOM, 255),
        Err(MatchProtocolError::InvalidOpcode(3))
    );
}
