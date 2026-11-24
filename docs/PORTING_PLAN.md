# PointBlankRust porting plan

Status date: 2026-11-24.

## Reference baseline

Primary working reference: [danimesq/point-blank-webport](https://github.com/danimesq/point-blank-webport), a fork of [LeandroDettmer/point-blank-webport](https://github.com/LeandroDettmer/point-blank-webport).

The reference tree has roughly 580 entries. It is a complete web-port stack rather than only a browser shell:

- TypeScript browser client built around Three.js and Rapier;
- TypeScript Auth and Game servers with PostgreSQL persistence;
- original Point Blank binary TCP protocol and packet definitions;
- peer-to-peer match core hosted by the room leader over WebRTC;
- data/config parsing, asset-export tooling, and protocol/integration tests.

The reference architecture document is the source of truth for component boundaries. This Rust port should preserve observable behavior and wire compatibility, not mechanically reproduce the TypeScript directory layout.

## Porting rules

1. **Compatibility before redesign.** Preserve packet bytes, opcode values, field widths, endianness, cipher behavior, and session sequencing. Use C#-derived vectors as golden tests.
2. **Separate protocol from transport.** Packet codecs must not depend on TCP, WebSocket, WebRTC, a database, or a renderer.
3. **Preserve authority boundaries.** The Game server remains authoritative for room flow, respawns, deaths, round/match endings, score, EXP, and currency. The peer-hosted match core handles real-time match datagrams and reports relevant events back to Game.
4. **Mark uncertainty.** Reconstructed or inferred behavior must be labelled in code and tests. Do not silently present it as original-game behavior.
5. **Do not import proprietary payloads.** Do not copy game executables, extracted assets, map/model/texture/audio payloads, or proprietary game data into this repository. Keep locally generated assets and client files out of Git.
6. **Keep platform choices open.** Do not choose a renderer, physics engine, desktop shell, or browser/WASM target until the required runtime and deployment targets are settled.

## Initial Rust workspace

| Crate | Responsibility | Status |
|---|---|---|
| **pb-protocol** | Packet primitives, TCP framing, CMess, bitwise cipher, compatibility vectors | Started in this foundation change |
| **pb-shared** | Shared domain types, item/rank/time helpers, validated static-data models | Planned |
| **pb-server** | Auth/Game services, TCP/WebSocket front doors, account API, PostgreSQL persistence | Planned |
| **pb-match** | Match datagrams, half-float math, host-side match core, host handoff | Planned |
| **pb-client-core** | Client state, lobby, inventory, room flow, input, gameplay orchestration | Planned |
| **pb-client-render** | Rendering, physics, audio, and platform integration | Planned; engine decision open |

Introduce crates when there is a concrete module to port. Empty placeholders are intentionally avoided.

## Conversion sequence

### 0. Protocol foundation

Create a dependency-light Rust library for packet read/write, stream framing, CMess, and bitwise primitives. Validate it against byte-for-byte vectors produced by the original C# implementation. This is the first implementation slice.

### 1. UDP protocol and shared data

Port the UDP 121 cipher and datagram layouts, half-float conversion, opcodes, and action codecs. Then define shared models for room identifiers, slots, equipment, item statistics, and map/object metadata. Keep golden vectors beside the codecs.

### 2. Server transport and authentication

Port session lifecycle, key exchange, rate limits, seed validation, and Auth packet handlers. Keep raw TCP and WebSocket transport adapters separate while preserving the browser bridge contract.

### 3. Game server and persistence

Port channels, rooms, player/social/clan state, inventory, shop, missions, votes, reports, progression, and database access. Preserve PostgreSQL compatibility initially. Schema changes should be explicit migrations rather than silent rewrites.

### 4. Peer-hosted match core

Port registration, player action replication, hit/damage validation, object synchronization, event handling, and host handoff. Preserve the split between Game authority and the match host. Bot/PVE behavior is a separate scope because the reference explicitly leaves some bot datagrams unimplemented.

### 5. Client core and UI

Port login, server/channel selection, lobby screens and state, room flow, loadout, match state, input, HUD models, and gameplay systems. UI rendering should consume client-core state rather than own protocol or game rules.

### 6. Rendering, physics, audio, and packaging

Only after the required platforms are chosen, port scene loading, character animation, weapons, collision, lighting, audio, caching, and platform integration. This stage needs its own renderer/physics decision and fidelity checklist.

## First protocol module: scope

The initial **pb-protocol** crate contains:

- **packet:** bounds-checked little-endian integer/float and fixed-width UTF-8/UTF-16LE fields;
- **cmess:** CMess encrypt/decrypt plus the Auth/Game session-seed LCG;
- **framing:** incremental server-frame decoder and encrypted client-frame builder;
- **bitwise:** cyclic whole-buffer bit rotation used by the UDP path.

The first tests cover C#-derived CMess, bitwise, and seed vectors, plus packet/framing edge cases. AES-CTR is deliberately excluded: the reference states it is not on the CMess TCP client/server path.

## Open design decisions

- Is the final client a native desktop app, a browser/WASM app, or both?
- Which rendering and physics backend best fits those targets?
- Should WebRTC remain the match transport, or is a native transport also required?
- Which parts of the existing data/config pipeline should remain external tools versus become Rust-native?
