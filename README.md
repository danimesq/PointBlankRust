# PointBlankRust

**Point Blank Web to Rust**

This repository is the Rust reimplementation of the Point Blank web port. The current reference implementation is [danimesq/point-blank-webport](https://github.com/danimesq/point-blank-webport), a fork of [LeandroDettmer/point-blank-webport](https://github.com/LeandroDettmer/point-blank-webport).

## Status

The first implementation slices are the protocol foundation and Match UDP codecs:

- little-endian packet reader and writer;
- CMess encryption/decryption and TCP packet framing;
- TCP server transport with bounded connections, per-client sessions, ordered frame dispatch and graceful shutdown;\n- Auth session bootstrap, CONNECT_ACK key material, CMess ingress, seed-window validation, rate limiting and typed opcode dispatch;
- UDP 121 encryption/decryption, Match datagram headers, room handshake and PVP/PING framing;
- binary16 position/coordinate conversion and Match action-record codecs;
- compatibility tests using byte-for-byte vectors from the original C# implementation.

The project is being migrated in small, verifiable layers. The browser client, game server, peer-hosted match core, rendering, physics and persistence remain separate concerns.

See:
- [Porting plan](docs/PORTING_PLAN.md)
- [Rust Gaming Eclipse integration contract](docs/RUST-GAMING-ECLIPSE.md)
- [Iroh multiplayer study: online and LAN](docs/IROH-MULTIPLAYER-STUDY.md)

## Development

Requires a stable Rust toolchain.

~~~sh
cargo fmt --all -- --check
cargo test --workspace
~~~

## Assets and game data

Game assets, executables, extracted files and proprietary Point Blank data do not belong in this repository. Use only a client and assets you are legally entitled to use, and keep generated assets outside version control. The reference project documents its asset-export workflow and legal boundaries.

## License

The license for this repository has not yet been selected.
