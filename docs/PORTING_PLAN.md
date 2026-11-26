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
| **pb-server-transport** | TCP listener, connection/session lifecycle and stream transport | Implemented; protocol callbacks are transport-neutral |
| **pb-auth** | Auth CONNECT handshake, per-session CMess ingress, seed validation, rate limits and opcode dispatch | Initial protocol/session layer implemented; account handlers pending |
| **pb-server** | Auth/Game services, WebSocket front doors, account API and PostgreSQL persistence | Planned |
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

**TCP transport is implemented and merged.** The independent `pb-server-transport` crate owns listener/session lifecycle and incremental TCP framing.

**Authentication protocol/session layer is implemented in `pb-auth`.** It generates the 1360-bit CONNECT_ACK key material, derives the 16-byte CMess client/server keys from the modified modulus, emits opcode 2306, decrypts client frames in MODE_AUTH, enforces the Auth first-packet allowlist (1281 LOGIN / 2309 KEEP_ALIVE), checks the next 16 LCG seeds, applies configurable packet token-bucket limits, and dispatches known Auth opcodes through typed handler interfaces.

The RSA operation is compatibility key-material generation only, not a modern security design: the reference does not use the generated RSA private key to encrypt the session. The first four modulus bytes are overwritten with SessionId + 29890, and the two 16-byte CMess keys are sliced from the resulting modulus. The reference seed generator uses `Random.Next(sessionId, 0x7fff)`; this makes session IDs above 32767 invalid for bootstrap, which is explicitly rejected rather than silently changing the range.

Remaining Authentication work: parse and validate the full LOGIN request body; implement token/account lookup, password and client-version checks, ban/MAC/IP policy, LOGIN decision flow, server/channel state and account metadata/inventory handlers; add per-IP connection throttles and first-packet/idle timeouts; and integrate raw-TCP/WebSocket adapters. The current crate includes wire builders for LOGIN_ACK, point-cash, USER_LEAVE, disconnect, account-kick and server-error replies, plus the reference ValidateKey function. Database-backed handlers belong in the future server service crate, not in the byte/session protocol crate.

Keep raw TCP and WebSocket transport adapters separate while preserving the browser bridge contract. The Auth session state machine accepts already-framed transport frames and does not own sockets, database connections, or WebSocket control messages.

### 2.1 Auth runtime integration

The next integration slice is implemented in pb-auth-runtime. It composes the existing Auth protocol/session crate, LOGIN service, PostgreSQL repository adapter and pb-server-transport callback contract:

- Allocate a protocol session ID in the original 1..32767 range.
- Generate CONNECT_ACK key material and send opcode 2306 as a plaintext server frame.
- Create one AuthSession per accepted transport session.
- Process encrypted client frames through CMess MODE_AUTH, first-opcode admission and the 16-step LCG seed window.
- Dispatch decoded packets through dispatch_auth_packet and run LOGIN through AuthService.
- Send LOGIN_ACK and GET_POINT_CASH_ACK as separate plaintext PB server frames.
- Send enterTicket only through an explicit WebSocket text-frame sink, as JSON text and before the PB login replies. Raw TCP deployments leave this side channel disabled; the ticket is never inserted into a PB binary packet.
- Release the account online/status claim when an authenticated session is destroyed. USER_LEAVE is treated as a Game handoff and does not clear online ownership.

The WebSocket text-frame sink is deliberately a host-provided adapter: pb-server-transport currently owns raw TCP sessions and cannot manufacture a WebSocket TEXT frame on a raw TCP socket. A WebSocket host must bind the sink to the same logical session and write an actual WebSocket text message. Enabling ticket delivery without such a sink fails the login output path instead of silently placing JSON in the binary stream.

The runtime currently wires LOGIN and the session lifecycle. Remaining Auth opcodes (server/channel state, inventory/account metadata and Game handoff operations beyond USER_LEAVE) need their corresponding service handlers before this is a complete production Auth server. The PostgreSQL adapter still uses its initial serialized single connection; pool/TLS deployment hardening remains a host concern.

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
