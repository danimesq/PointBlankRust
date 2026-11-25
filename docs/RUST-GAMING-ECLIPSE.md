# Rust Gaming Eclipse: PointBlankRust integration contract

**Status:** Architecture and integration plan, 2026-11-25.  
**Scope:** Position PointBlankRust in the cross-repository Rust Gaming Eclipse strategy and define its boundaries with RustMultiConsoleFoundation, StreetChavesRust, and ImpossibleEngine.  
**Implementation status:** This document records architecture and sequencing. It does not add runtime dependencies or claim that any new renderer, Foundation adapter, Bevy bridge, or console target is already implemented.

## 🌘 1. PointBlankRust's place in Rust Gaming Eclipse

Rust Gaming Eclipse is the alignment of three independent projects:

| Repository | Owns | Must not own |
|---|---|---|
| **RustMultiConsoleFoundation** | Reusable platform contracts, capability profiles, host adapters, target-specific asset adaptation, toolchain/build orchestration, packaging and validation | Point Blank gameplay, protocol semantics, ImpossibleEngine Event Sheet semantics |
| **ImpossibleEngine** | Authoring/project model, Event Sheets, semantic schema, typed IR, compiler/lowering, generated project composition and target selection | Point Blank networking/game rules or generic platform adapters |
| **StreetChavesRust** | Street Chaves domain, source-derived deterministic simulation, its game data and compatibility tests | Generic platform runtime or compiler abstractions |
| **PointBlankRust** | Point Blank domain and wire compatibility, Auth/Game/Match networking, player/room/match behavior, 3D FPS client and its source-derived assets/data adapters | Generic Foundation platform services, ImpossibleEngine compiler semantics, Street Chaves game rules |

The first three repositories form the original Eclipse architecture. **PointBlankRust is an additional, intentionally demanding consumer and end-to-end validation project**, especially for 3D rendering and first-person gameplay. It is not a fourth implementation of the Foundation, and the three foundational projects must not merge into a monorepo merely to integrate the games.

The dependency direction remains one-way:

~~~text
      StreetChavesRust       ImpossibleEngine        PointBlankRust
        2D game core           editor/compiler          3D FPS
              \                    |                    /
               \                   |                   /
                +------------------+------------------+
                                   |
                                   v
                      RustMultiConsoleFoundation
                  public contracts · capabilities · adapters
                     asset adaptation · build · packaging
                                   |
                                   v
                      validated platform/host adapters
~~~

The Foundation must never depend on PointBlankRust, StreetChavesRust, or ImpossibleEngine. PointBlankRust may consume a versioned, public Foundation API independently when the API and required adapter are real and validated. It must not depend on StreetChavesRust or on the ImpossibleEngine compiler to build or run.

## 🌘 2. Why PointBlankRust is a distinct validation workload

StreetChavesRust is a valuable 2D, deterministic-simulation and source-compatibility consumer. PointBlankRust exercises a materially different workload:

- 3D models, geometry, materials, textures, animation and spatial assets;
- first-person camera, view-space effects, weapons, projectiles and hit registration;
- scene loading, collision/physics, visibility and audio;
- real-time multiplayer transport, server authority, peer-hosted match behavior and reconnect/handoff;
- lobby, inventory, room, account and progression flows;
- different memory, GPU, bandwidth, latency, storage and asset-budget constraints by target.

A successful StreetChaves Foundation integration therefore does not prove that PointBlank's 3D renderer, asset pipeline, networking or match loop will work on the same target. Likewise, a successful PointBlank desktop build does not prove that a constrained console profile is supported.

Use PointBlankRust to validate the Foundation's ability to support a demanding 3D consumer without leaking target-specific APIs into the game domain. Record each capability independently.

## 🌘 3. Preserve PointBlankRust's own domain and protocol boundaries

The current Rust port starts with a transport-independent **pb-protocol** crate. That separation is intentional and remains true under Eclipse:

| Concern | Owner |
|---|---|
| Packet layouts, byte order, opcodes, CMess, UDP 121, datagram/action codecs | **PointBlankRust / pb-protocol** |
| Account, Auth/Game session rules, channel/room/inventory progression | **PointBlankRust / future server-domain crates** |
| Match authority, player actions, hits, deaths, score and round flow | **PointBlankRust / future server and match crates** |
| Game state, input meaning, weapon/camera behavior, simulation and gameplay policy | **PointBlankRust** |
| Renderer-neutral scene/frame intent and logical asset identities | **PointBlankRust** |
| Window/event loop, physical input normalization, display/audio/storage services | **Foundation adapter or an explicitly selected engine host, once validated** |
| Actual rendering, GPU resources, shader/material support and target resource lifecycle | **Selected renderer/engine adapter** |
| Target capability profile, canonical-to-target asset conversion, toolchain, build/package metadata | **RustMultiConsoleFoundation** |

Networking is not silently moved into the Foundation just because it is a cross-platform concern. The packet and game-session semantics stay in PointBlankRust. Any future host-level network abstraction must be justified by concrete target requirements and must not alter the wire contract or authority model.

The Foundation must not learn about Point Blank opcodes, room IDs, weapon IDs, damage rules, CMess, UDP 121 or Point Blank asset formats as game semantics. It can provide generic build, target, storage, timing or device facilities only through platform-neutral APIs.

## 🌘 4. Foundation integration is gated, not guessed

The initial foundation-runtime scaffold is a documented contract step, not a production cross-platform game runtime. It does not by itself establish a production SDL adapter, native renderer, browser host, audio backend, storage implementation or classic-console support.

Before PointBlankRust adds a Foundation dependency, the Foundation must provide:

1. A real public workspace crate and documented module path.
2. A versioned API, feature matrix, MSRV and compatibility policy.
3. A target/capability profile with explicit supported, unavailable, emulated, degraded and unknown states.
4. At least one validated host adapter relevant to the selected PointBlank target.
5. A headless/mock implementation for protocol, simulation and server tests.
6. A minimal compiling consumer example, including actionable errors for unsupported capabilities.
7. A documented way to resolve logical assets to target-specific assets without coupling gameplay code to the host backend.

Until then:
- Keep the current PointBlankRust code independent of the Foundation.
- Do not invent a crate name or import path.
- Do not add a Git dependency on a moving branch.
- Do not remove working local host code merely because an API is proposed.
- Pin an immutable Git revision during early integration; move to semver once the Foundation publishes a release.

## 🌘 5. Platform, host, engine and physics are separate decisions

A PointBlank build is a combination of independent axes:

| Axis | Examples | Decision meaning |
|---|---|---|
| Target platform | Windows, Linux, Web, Android, PSP, PS1, N64, GBA | Where the build is intended to run |
| Host/runtime | Foundation-native adapter, browser host, console SDK, specialized runtime | How system services are reached |
| Rendering/game engine | Custom renderer, Bevy-hosted client, another validated renderer | How 3D scenes and game systems are organized |
| Physics provider | PointBlank-specific collision rules, standalone Rapier, Bevy Rapier or another provider | How physics/collision workloads are calculated |

Do not infer support for a console from CPU code generation, an LLVM target, a packaging profile or a successful boot test. A target is not game-supported until its ABI/linking, startup/runtime, graphics, input, audio, storage/network needs, assets, packaging and gameplay are independently validated.

### Bevy policy

Bevy is an optional client-engine/runtime experiment, not the Foundation and not a universal platform backend. A Bevy-hosted PointBlank client would let Bevy own its app schedule and Bevy-managed window/input/rendering path. A future Foundation bridge may adapt compatible Foundation capabilities to Bevy resources/plugins, but it must not create a second window, event loop, renderer, input path or audio owner.

Keep pb-protocol, server-domain crates and match-domain codecs independent of Bevy. Do not convert protocol or gameplay ownership into ECS components merely to adopt an engine.

### Rapier policy

Rapier is a physics provider, not a platform adapter. It may be evaluated for suitable 3D collision/rigid-body workloads, either standalone or through a matching Bevy plugin. Its adoption must not silently change hit registration, weapon traces, movement, collision filtering, prediction or authoritative server rules. Keep compatibility-sensitive behavior behind explicit game-owned interfaces and compare any candidate provider with deterministic fixtures.

Bevy and Rapier dependencies must remain optional and scoped to the concrete client/target experiment. Their compatibility and target support must be validated before they become build requirements.

## 🌘 6. 3D asset and capability strategy

PointBlank's assets cannot be treated as one universal bundle. The same logical asset may need different realizations for modern desktop, browser, mobile and constrained console targets.

The game should own stable logical identities and the meaning of assets. A target pipeline may select or produce different physical resources:

- high-detail meshes, textures and materials for capable desktop targets;
- reduced geometry, texture sizes/formats and effects for tighter GPU/memory budgets;
- target-specific animation or skeleton reductions where validated;
- alternate audio formats, sample rates, channels or compressed banks;
- lower-resolution UI and target-specific input prompts;
- explicit substitutions or unsupported-feature diagnostics where a target cannot represent a feature.

The Foundation may own generic capability profiles, asset conversion orchestration and packaging integrations. It must not own Point Blank weapon definitions, map rules, model semantics, damage tables or proprietary source data.

Do not commit game executables, extracted proprietary assets, copyrighted audio, map/model/texture payloads or other non-redistributable content unless the repository has a documented right to distribute each item. Keep local asset caches and generated target builds outside source control. Preserve provenance for any asset converted or imported.

## 🌘 7. ImpossibleEngine relationship: possible authoring path, not a runtime dependency

ImpossibleEngine owns project authoring, versioned Event Sheet data, semantic analysis, typed IR, lowering and generated project composition. PointBlankRust owns Point Blank game rules and its existing native implementation. The Foundation owns generic platform adapters and build/asset services.

The intended compiler boundary is:

~~~text
Impossible project/schema
        |
        v
typed Event Sheet IR + semantic validation
        |
        v
target lowering / generated project composition
        |
        +------> PointBlank native Rust modules (explicit interfaces)
        |
        v
RustMultiConsoleFoundation public contract
        |
        v
selected target adapter + assets + build/package
~~~

This is a possible long-term authoring/import path, not a current PointBlank dependency or a promise of lossless conversion. ImpossibleEngine must not become the authority for Point Blank protocol ordering, networking, match state, weapon rules or security-sensitive server decisions.

If PointBlank is ever imported into ImpossibleEngine:
- preserve source and asset provenance;
- map only constructs whose semantics have a complete, tested representation into typed IR;
- keep complex, timing-sensitive, network/security-sensitive or performance-critical systems as native Rust modules behind explicit contracts;
- represent unsupported constructs as diagnostics rather than approximating or dropping them;
- compare each migrated slice against PointBlankRust's native behavior with deterministic fixtures;
- do not claim complete/lossless import until all required semantics have verified mappings.

A generated project may use a Foundation runtime on supported native/Web targets, or a specialized lowering path on constrained systems. The compiler must not force one runtime onto every target.

## 🌘 8. Recommended implementation and validation order

1. **Protocol baseline (current work):** finish TCP/UDP codecs and wire-vector tests without host or renderer dependencies.
2. **Shared game-domain types:** define only the cross-client/server data that has concrete consumers; keep protocol byte types distinct from higher-level domain types.
3. **Server transport and Auth:** port session lifecycle, key exchange, rate limits, seed validation and Auth handlers.
4. **Game server and persistence:** port room/channel/player/inventory/shop/progression flows with explicit schema migrations.
5. **Peer-hosted match core:** port datagrams, action replication, hit/damage validation, object sync and host handoff while preserving authority boundaries.
6. **Client core:** port login, lobby, room, loadout, input and gameplay orchestration independently of a renderer.
7. **3D client experiment:** compare a custom renderer with optional Bevy-hosted mode on one declared target; measure startup, build size, memory, frame time, shader/material needs, asset loading and browser behavior.
8. **Physics experiment:** evaluate the selected physics provider separately, with weapon/hit/collision fixtures.
9. **Foundation consumer integration:** add one minimal adapter for one validated target only after the Foundation API release gates are met.
10. **Target expansion:** add per-target asset variants, capability records, packaging and emulator/hardware validation without weakening the compatibility baseline.
11. **ImpossibleEngine interoperability:** define an interchange/import boundary only after the compiler has typed semantics and a concrete native-module composition model.

Do not block protocol/server correctness on a renderer or Foundation runtime decision. Do not block the Foundation's generic API on PointBlank-specific requirements.

## 🌘 9. Acceptance criteria for the PointBlank consumer

A target is an accepted PointBlank target only when all required items are demonstrated for that target:

- The required Rust target/toolchain, ABI, linker and startup path are documented and reproducible.
- Required host capabilities are available or have explicit, tested fallbacks.
- 3D scene/model/texture/material loading and presentation work within recorded memory/GPU budgets.
- Input, audio, storage and networking requirements are independently validated.
- A representative first-person gameplay loop runs and preserves the intended simulation and weapon behavior.
- Protocol compatibility tests pass independently of the renderer.
- Multiplayer smoke tests validate room registration, action replication, hit/death/reporting flow, reconnect and failure handling where that target supports networking.
- The artifact can be built, packaged, launched and tested in a declared emulator and, where possible, physical hardware.
- Unsupported capabilities and asset substitutions are reported, never silently claimed as supported.

Desktop, Web, mobile and each classic-console target need separate evidence. There is no blanket "cross-platform" pass.

## 🌘 10. Current decisions and non-goals

Decisions:
- PointBlankRust remains a separate Rust project and does not become a Foundation, StreetChavesRust or ImpossibleEngine subcrate.
- pb-protocol stays transport- and renderer-independent.
- Foundation integration is deferred until the public API and a relevant host adapter pass their release gates.
- Bevy/Rapier remain optional experiments, not assumed dependencies.
- PointBlank is a future demanding 3D validation consumer in the wider multi-console strategy.

Non-goals:
- No repository merge or shared workspace across the four projects.
- No direct dependency from Foundation to PointBlankRust, StreetChavesRust or ImpossibleEngine.
- No immediate renderer or physics-engine selection.
- No claim that Bevy, Rapier, SDL, WASM or any console target is already integrated or validated.
- No wholesale translation of PointBlank gameplay into Event Sheets.
- No weakening of Point Blank wire compatibility to accommodate a host/engine abstraction.

## 🌘 11. Cross-repository references

- [RustMultiConsoleFoundation: Rust Gaming Eclipse](https://github.com/danimesq/RustMultiConsoleFoundation/blob/main/docs/rust-gaming-eclipse.md)
- [RustMultiConsoleFoundation: multi-console architecture](https://github.com/danimesq/RustMultiConsoleFoundation/blob/main/docs/multi-console-foundation.md)
- [StreetChavesRust: Rust Gaming Eclipse integration plan](https://github.com/danimesq/StreetChavesRust/blob/main/docs/rust-gaming-eclipse.md)
- [ImpossibleEngine: Rust Gaming Eclipse integration plan](https://github.com/danimesq/ImpossibleEngine/blob/main/docs/RUST-GAMING-ECLIPSE.md)
