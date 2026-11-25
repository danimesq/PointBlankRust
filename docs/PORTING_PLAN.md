# PointBlankRust porting plan

Status date: 2026-11-25.

## Reference baseline

Primary working reference: [danimesq/point-blank-webport](https://github.com/danimesq/point-blank-webport), a fork of [LeandroDettmer/point-blank-webport](https://github.com/LeandroDettmer/point-blank-webport).

The reference tree is a complete web-port stack rather than only a browser shell:

- TypeScript browser client built around Three.js and Rapier;
- TypeScript Auth and Game servers with PostgreSQL persistence;
- original Point Blank binary TCP protocol and packet definitions;
- peer-to-peer match core hosted by the room leader over WebRTC;
- data/config parsing, asset-export tooling, and protocol/integration tests.

The reference architecture document is the source of truth for component boundaries. This Rust port should preserve observable behavior and wire compatibility, not mechanically reproduce the TypeScript directory layout.

## Porting rules

1. **Compatibility before redesign.** Preserve packet bytes, opcode values, field widths, endianness, cipher behavior and session sequencing. Use C#-derived vectors as golden tests.
2. **Separate protocol from transport.** Packet codecs must not depend on TCP, UDP sockets, WebSocket, WebRTC, a database or a renderer.
3. **Preserve authority boundaries.** The Game server remains authoritative for room flow, respawns, deaths, round/match endings, score, EXP and currency. The peer-hosted match core handles real-time match datagrams and reports relevant events back to Game.
4. **Mark uncertainty.** Reconstructed or inferred behavior must be labelled in code and tests. Do not silently present it as original-game behavior.
5. **Do not import proprietary payloads.** Do not copy game executables, extracted assets, map/model/texture/audio payloads or proprietary game data into this repository. Keep locally generated assets and client files out of Git.
6. **Keep platform choices open.** Do not choose a renderer, physics engine, desktop shell or browser/WASM target until the required runtime and deployment targets are settled.

## Initial Rust workspace

| Crate | Responsibility | Status |
|---|---|---|
| **pb-protocol** | Packet primitives, TCP framing, CMess, UDP 121, Match datagrams/actions, half-float conversion and wire vectors | Active |
| **pb-shared** | Shared domain types, item/rank/time helpers and validated static-data models | Planned |
| **pb-server** | Auth/Game services, TCP/WebSocket front doors, account API and PostgreSQL persistence | Planned |
| **pb-match** | Match datagrams, host-side match core, hit/damage validation and host handoff | Planned |
| **pb-client-core** | Client state, lobby, inventory, room flow, input and gameplay orchestration | Planned |
| **pb-client-render** | Rendering, physics, audio and platform integration | Planned; engine decision open |

Introduce crates when there is a concrete module to port. Empty placeholders are intentionally avoided. UDP wire codecs live in pb-protocol; match simulation/authority will live in higher-level match/server crates.

## Conversion sequence

### 0. TCP protocol foundation

Create a dependency-light Rust library for packet read/write, stream framing, CMess and the session-seed LCG. Validate it against byte-for-byte vectors produced by the original C# implementation. **Completed and merged.**

### 1. Match UDP protocol and action records

Port the UDP 121 C2S/S2C cipher, plaintext Match header, REGISTER/UNREGISTER handshake, PING and PVP datagrams, half-float conversion, action flags and record layouts. Validate both directions using C#-derived datagram vectors and exact action-record bytes.

The codec crate does not own sockets, session lifecycle, room state, hit validation or gameplay authority. It exposes deterministic encode/decode functions and accepts injected randomness.

### 2. Server transport and authentication

Port session lifecycle, key exchange, rate limits, seed validation and Auth packet handlers. Keep raw TCP and WebSocket transport adapters separate while preserving the browser bridge contract.

### 3. Game server and persistence

Port channels, rooms, player/social/clan state, inventory, shop, missions, votes, reports, progression and database access. Preserve PostgreSQL compatibility initially. Schema changes should be explicit migrations rather than silent rewrites.

### 4. Peer-hosted match core

Port registration, player action replication, hit/damage validation, object synchronization, event handling and host handoff. Preserve the split between Game authority and the match host. Bot/PVE behavior is a separate scope because the reference explicitly leaves some bot datagrams unimplemented.

### 5. Client core and UI

Port login, server/channel selection, lobby screens and state, room flow, loadout, match state, input, HUD models and gameplay systems. UI rendering should consume client-core state rather than own protocol or game rules.

### 6. Rendering, physics, audio and packaging

Only after the required platforms are chosen, port scene loading, character animation, weapons, collision, lighting, audio, caching and platform integration. This stage needs its own renderer/physics decision and fidelity checklist.

## Rust Gaming Eclipse relationship

PointBlankRust is an independent, demanding 3D/FPS consumer in the wider Rust Gaming Eclipse strategy. It is not one of the three foundational repositories and must not be merged into a shared workspace with them.

- RustMultiConsoleFoundation owns generic platform contracts, target capabilities, adapters, asset adaptation and build/package tooling.
- ImpossibleEngine owns project authoring, Event Sheets, typed semantics, compiler/lowering and generated-project composition.
- StreetChavesRust owns its own 2D game domain and serves as an early deterministic/reference consumer.
- PointBlankRust owns Point Blank protocol, account/server/match behavior, first-person gameplay and game-specific asset meaning.

PointBlank may consume a versioned Foundation API only after its public crate and a relevant target adapter are validated. It must not depend on StreetChavesRust or the ImpossibleEngine compiler to build or run. Protocol/gameplay semantics remain PointBlank-owned; target host services and generic asset/build facilities may be delegated through explicit contracts later.

See [RUST-GAMING-ECLIPSE.md](RUST-GAMING-ECLIPSE.md) for dependency direction, Foundation release gates, optional Bevy/Rapier policy, 3D asset adaptation, target acceptance criteria and the possible future ImpossibleEngine import boundary.

## Open design decisions

- Is the final client a native desktop app, a browser/WASM app or both?
- Which rendering and physics backend best fits those targets?
- Should WebRTC remain the match transport, or is a native transport also required?
- Which parts of the existing data/config pipeline should remain external tools versus become Rust-native?
- Which target profile should be the first end-to-end 3D validation target?
