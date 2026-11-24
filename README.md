# PointBlankRust

**Point Blank Web to Rust**

This repository is the Rust reimplementation of the Point Blank web port. The current reference implementation is [danimesq/point-blank-webport](https://github.com/danimesq/point-blank-webport), a fork of [LeandroDettmer/point-blank-webport](https://github.com/LeandroDettmer/point-blank-webport).

## Status

The first implementation slice is the protocol foundation:

- little-endian packet reader and writer;
- CMess encryption/decryption and packet framing;
- UDP bitwise rotation and session-seed generation;
- compatibility tests using byte-for-byte vectors produced from the original C# implementation.

The project is being migrated in small, verifiable layers. The browser client, game server, peer-to-peer match core, rendering, physics, and persistence are separate concerns; see [docs/PORTING_PLAN.md](docs/PORTING_PLAN.md).

## Development

Requires a stable Rust toolchain.

~~~sh
cargo test -p pb-protocol
~~~

## Assets and game data

Game assets, executables, extracted files, and proprietary Point Blank data do not belong in this repository. Use only a client and assets you are legally entitled to use, and keep generated assets outside version control. The reference project documents its asset-export workflow and legal boundaries.

## License

The license for this repository has not yet been selected.
