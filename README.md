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

## Development

Requires a stable Rust toolchain.

~~~sh
cargo fmt --all -- --check
cargo test --workspace
~~~

## Come with your own binary\n\nPointBlankRust does not distribute the Point Blank executable, installer, client data, extracted assets or proprietary game files. Bring a client copy you are legally entitled to use (the classic “come with your own binary” model) and keep it outside version control.\n\nObtain the client from the official publisher for your region whenever possible. Download methods vary by publisher, region and client version. This is not hypothetical: the official Point Blank Türkiye download portal documents both **Quick Download** and **Torrent** options, and its installation guide explicitly describes **Full Client Download** and **Torrent Client Download**:\n\n- [Official Point Blank Türkiye download page](https://pb.tamgame.com/game/download)\n- [Official Point Blank Türkiye installation guide](https://pb.tamgame.com/game/init)\n\nThe official page notes that a BitTorrent application is required for the torrent option. This documents an official regional distribution channel, not a guarantee that a torrent is currently offered in Brazil or for every Point Blank build. Do not substitute unofficial mirrors, repacks or private-server bundles for an official client.\n\nSuggested local layout (never commit the client):\n\n~~~text\nPointBlankRust/\n  Clients/\n    PointBlank/\n      PointBlank.exe\n      Pack/\n~~~\n\nKeep local client paths ignored by Git. Do not upload executables, .torrent files, magnet links, extracted proprietary data or generated game assets to this repository.\n\n## Assets and game data

Game assets, executables, extracted files and proprietary Point Blank data do not belong in this repository. Use only a client and assets you are legally entitled to use, and keep generated assets outside version control. The reference project documents its asset-export workflow and legal boundaries.

## License

The license for this repository has not yet been selected.
