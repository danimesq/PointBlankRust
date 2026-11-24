//! Golden vectors compiled from the original C# implementation.
//! Fixture source: danimesq/point-blank-webport/src/net/test/vectors.json.
//! AES-CTR vectors are intentionally excluded because AES-CTR is not part of
//! the CMess TCP path covered by this crate.

use pb_protocol::bitwise::{bitwise_decrypt, bitwise_encrypt};
use pb_protocol::cmess::{
    cmess_decrypt, cmess_encrypt_with_random, next_session_seed, CmessRandom, MODE_AUTH,
    MODE_GAME,
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

#[test]
fn cmess_encrypt_and_decrypt_match_csharp_vectors() {
    const KEY: &str = "031425364758697a8b9cadbecfe0f102";

    let vectors = [
        (MODE_AUTH, "", "252c53041d11d750"),
        (MODE_AUTH, "07", "0c00bd03097e9053"),
        (MODE_AUTH, "07264564", "3b09c4081834685fca34d1d9a689d651"),
        (
            MODE_AUTH,
            "0726456483a2c1e0ff1e3d5c7b9ab9d8",
            "1b111904987739ba277ec826f83616a7a7b56dd3dc7ab11e",
        ),
        (MODE_GAME, "", "1b120904c771deda"),
        (MODE_GAME, "07", "1f00f203dfea3813"),
        (MODE_GAME, "07264564", "20287e08652b8e50cae8dc8611d7bb2d"),
        (
            MODE_GAME,
            "0726456483a2c1e0ff1e3d5c7b9ab9d8",
            "170b23044b98a51c09a91548f46721d488bd41d7b0dd57b7",
        ),
    ];

    let key = from_hex(KEY);
    for (mode, plaintext_hex, ciphertext_hex) in vectors {
        let plaintext = from_hex(plaintext_hex);
        let ciphertext = from_hex(ciphertext_hex);
        let random = CmessRandom {
            r0: ciphertext[0],
            r1: ciphertext[1],
            r2: ciphertext[2],
        };

        assert_eq!(
            cmess_encrypt_with_random(&key, &plaintext, mode, random).unwrap(),
            ciphertext,
            "CMess encryption mode {mode}, plaintext length {}",
            plaintext.len()
        );
        assert_eq!(
            cmess_decrypt(&key, &ciphertext, mode).unwrap(),
            plaintext,
            "CMess decryption mode {mode}"
        );
    }
}

#[test]
fn bitwise_cipher_matches_csharp_vectors() {
    let vectors = [
        (1, "05223f5c7996b3d0ed", "0a447eb8f32d67a1da"),
        (3, "05223f5c7996b3d0ed", "2911fae3ccb59e8768"),
        (7, "05223f5c7996b3d0ed", "911fae3ccb59e87682"),
    ];

    for (shift, plaintext_hex, ciphertext_hex) in vectors {
        let plaintext = from_hex(plaintext_hex);
        let ciphertext = from_hex(ciphertext_hex);
        assert_eq!(bitwise_encrypt(&plaintext, shift).unwrap(), ciphertext);
        assert_eq!(bitwise_decrypt(&ciphertext, shift).unwrap(), plaintext);
    }
}

#[test]
fn session_seed_lcg_matches_csharp_vectors() {
    let vectors: [(i32, [u16; 6]); 5] = [
        (0, [38, 162, 567, 1890, 6210, 20317]),
        (1, [41, 172, 600, 1997, 6559, 21457]),
        (12345, [7584, 24804, 15502, 17893, 25701, 18431]),
        (32767, [8737, 28569, 27796, 25272, 17030, 22883]),
        (65535, [17440, 24222, 13601, 11685, 5428, 17764]),
    ];

    for (initial, expected) in vectors {
        let mut seed = initial;
        let mut actual = Vec::with_capacity(expected.len());

        for _ in 0..expected.len() {
            let next = next_session_seed(seed);
            actual.push(next);
            seed = i32::from(next);
        }

        assert_eq!(actual.as_slice(), &expected);
    }
}
