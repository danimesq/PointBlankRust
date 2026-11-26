# Iroh multiplayer study: online and LAN

**Status:** Architecture study, 2026-11-25  
**Scope:** Evaluate Iroh as a native Rust peer-to-peer transport for Point Blank matches over the public internet and local networks.  
**Decision:** Recommend a small native-client prototype behind a transport abstraction. Do not add Iroh to the workspace, replace the current TCP/Auth transport, or remove the WebRTC browser path as part of this study.

## 1. Executive summary

Iroh is a strong candidate for the **native Rust multiplayer transport** because it combines:

- Peer connections authenticated by cryptographic endpoint identity.
- QUIC connections with end-to-end encryption.
- Direct connectivity attempts using NAT traversal / hole punching.
- Relay fallback when direct paths cannot be established.
- Reliable, independently multiplexed QUIC streams.
- Unreliable, unordered QUIC application datagrams.
- Address lookup and discovery, including a local-network mDNS-style companion crate.

This maps naturally to the existing Point Blank match split:

| Existing match traffic | Candidate Iroh primitive |
|---|---|
| Positions, movement/actions and replaceable HP snapshots | QUIC application datagrams |
| Hits, grenades, weapon drops, radio and mission events | Reliable QUIC streams |
| Match bootstrap, room membership, host handoff and state snapshots | Reliable bidirectional streams |
| Peer identity and encrypted transport | Iroh EndpointId + QUIC/TLS |

The mapping is conceptual, not a claim that Iroh is a drop-in replacement for WebRTC DataChannels or raw UDP. Datagram size limits, congestion behavior, framing, reconnect semantics and real latency must be measured.

**Recommended direction:** preserve the existing protocol and match-core boundaries, keep WebRTC for the browser client, and prototype an optional Iroh backend for native Rust clients. Iroh should solve connectivity and transport. It must not become the authority for Point Blank gameplay, account state or match outcomes.

## 2. Point Blank's current architecture and constraints

The WebPort reference (danimesq/point-blank-webport) already runs peer-hosted matches:

- The room leader hosts the match core in a Web Worker.
- Other players connect to the leader through WebRTC.
- Two data channels are used per player:
  - An unordered channel carries positions, actions and HP; late packets may be dropped.
  - A reliable channel carries hits, grenades, weapon drops, radio and mission events.
- The Game server remains authoritative for room flow, respawns, deaths, round/match endings, score, EXP and gold.
- The host runs match datagrams and the mode-specific rules that need host execution, including HeadHunter/Chaos damage and Sabotage objective hits.
- A leader departure causes the server to select a new leader. If the old tab is still alive during a planned handoff, it transfers match state to the new host. If it crashes, some volatile state is lost and the reference recovers with its documented fallback behavior.

The Rust port intentionally keeps:
- **pb-protocol** responsible for byte layouts, CMess, UDP 121 and Match datagram/action codecs.
- **pb-server-transport** responsible for TCP listener and connection/session lifecycle.
- Future Game and Match crates responsible for application state and match authority.

The porting plan explicitly leaves the choice between retaining WebRTC and adding a native transport open. This study addresses that decision without changing those boundaries.

## 3. What Iroh provides

### 3.1 Endpoint identity and connection establishment

An Iroh Endpoint has a SecretKey; its public key is the EndpointId. Peers connect to an endpoint identity plus addressing information and an ALPN protocol identifier. The remote endpoint identity is authenticated as part of the encrypted QUIC connection.

An application must still authorize the peer. A valid EndpointId proves possession of the corresponding endpoint key; it does **not** prove that the peer owns a particular Point Blank account, belongs to a room, is the current host, or may send gameplay events.

Iroh recommends one Endpoint per application process so its peer-to-peer connections can share the endpoint's network state.

### 3.2 Internet connectivity: direct first, relay fallback

The usual connection path is:

1. Endpoints discover addressing information, commonly including a home relay URL.
2. The endpoints establish connectivity through the relay-assisted path.
3. Iroh attempts QUIC NAT traversal / hole punching to establish a direct peer-to-peer path.
4. If a direct path succeeds, traffic migrates away from the relay.
5. If direct connectivity cannot be established, encrypted traffic can continue through a relay.

This is relevant to players behind home routers, carrier-grade NAT (CGNAT), restrictive firewalls or networks where inbound port forwarding is unavailable.

A relay is not the match server: it forwards encrypted packets addressed to endpoint identities and does not decrypt the match payload. It still introduces a network hop, bandwidth usage, availability dependency and metadata exposure. Relay deployment, operational ownership, capacity, geographic placement and cost need an explicit decision. A self-hosted relay should be evaluated alongside public relay infrastructure.

Iroh does not guarantee a direct path through every NAT/firewall combination. Relay fallback is an essential part of the connectivity design, not an exceptional bug path.

### 3.3 LAN discovery and offline local play

For current Iroh 1.x, local mDNS-style address lookup is available as the companion crate **iroh-mdns-address-lookup**. Its documentation describes discovery of local endpoints without a relay or outside internet connection.

This distinction matters: older iroh-net documentation describes LocalSwarmDiscovery and the discovery-local-network feature. The current 1.5.0 line documents the separate iroh-mdns-address-lookup crate. Do not copy an old iroh-net API snippet into a new implementation without checking the selected Iroh release.

A LAN setup can therefore combine:
- A native Iroh Endpoint.
- Local mDNS address lookup.
- Direct local IP paths.
- A LAN lobby/room announcement mechanism.
- A local match host or a dedicated server on the same subnet.

A local-only match should be able to run without contacting a public relay, DNS service or Internet directory when peers already discover one another on the LAN and direct routes are allowed.

**mDNS is discovery, not a connectivity guarantee.** It generally does not cross routers/VLANs, and Wi-Fi client isolation, multicast filtering, host firewalls and platform permissions can prevent discovery or peer-to-peer traffic. The client needs manual invite/address entry or a LAN directory fallback for networks where multicast is blocked.

Separate two LAN product modes:

1. **LAN transport with online account services:** authentication/lobby may still use the central Game/Auth services, while match traffic prefers direct local peer paths.
2. **Fully offline LAN:** a local host/dedicated server must also provide the required room, membership and authority functions. Iroh alone does not create offline accounts, room state, persistence or a Game server.

### 3.4 QUIC streams and datagrams

Iroh exposes QUIC streams and application datagrams:

- Streams are reliable and ordered within each stream. Multiple streams can progress independently, avoiding cross-stream head-of-line blocking.
- A connection can carry multiple uni- or bidirectional streams.
- Application datagrams are unreliable and unordered. They may be lost or arrive out of order.
- Datagram payloads must fit in a single QUIC packet and obey the current peer/path maximum. The maximum may change with path MTU and can be unavailable when datagrams are disabled or unsupported.

This is a good conceptual match for the WebPort's two-channel design. It is not a one-to-one API replacement: QUIC datagrams are carried inside an encrypted QUIC connection and have different size, congestion and path behavior from WebRTC data channels or standalone UDP sockets.

## 4. Proposed Point Blank transport mapping

Keep **pb-protocol** transport-neutral. A candidate native transport adapter should carry the existing application payloads without moving packet parsing, game rules or authority into Iroh-specific code.

### 4.1 Unreliable real-time lane

Use QUIC application datagrams for data where a newer update supersedes an older one:

- Position / movement updates.
- Frequent action-state snapshots.
- HP or other replaceable state snapshots, where existing protocol semantics permit it.
- Time-sensitive transient state that is safe to lose and can be refreshed.

Potential envelope fields, subject to measurement:
- Protocol/version discriminator.
- Match ID and match epoch.
- Sender/player slot.
- Sequence number or tick.
- Existing Point Blank datagram payload bytes.

The sequence/tick data allows the receiver to reject stale, duplicate or out-of-window updates. Do not add fields to an original Point Blank packet unless the transport envelope is explicitly outside that packet and compatibility tests prove the inner payload remains unchanged.

Check Connection::max_datagram_size() at runtime. Do not assume every existing UDP 121 payload fits. Oversized data must be split at an application-defined layer or sent over a reliable stream; it must never be silently truncated. Fragmentation should be avoided for high-frequency movement data because loss of one fragment can invalidate the whole update.

### 4.2 Reliable event lane

Use one or more long-lived bidirectional streams for events that must be delivered:

- Hit reports and validated hit results.
- Grenade events.
- Weapon drops and pickups.
- Radio events.
- Mission/objective events.
- Match-control messages that require ordered delivery.

Use explicit length-delimited framing because QUIC streams are byte streams, not message queues. Include sequence IDs and idempotency rules where retries or reconnects could otherwise apply an event twice.

Prefer separate streams for independent traffic classes (for example, gameplay events versus bulk state transfer) so a large snapshot does not block latency-sensitive reliable events on the same stream. Apply bounded queues, backpressure and explicit size limits.

### 4.3 Bootstrap and control lane

Use reliable streams for:
- Match protocol version negotiation.
- Room/match ID and epoch confirmation.
- Player slot and role assignment.
- Server-issued match admission ticket.
- Initial state and late-join synchronization.
- Reconnect/resume negotiation.
- Planned host handoff and state snapshot transfer.

ALPN should identify a versioned Point Blank match protocol, for example **pb-match/1**. ALPN is protocol negotiation, not player authorization.

## 5. Online match flow with Iroh

A candidate flow for a native client:

1. The player logs in through the existing Auth/Game path. Do not replace the Point Blank TCP/CMess handshake as part of the Iroh experiment.
2. The Game server creates/updates the room and selects the match leader using the existing room policy.
3. Each native client starts or reuses its process-level Iroh Endpoint and obtains its EndpointId/address information.
4. The Game service distributes the leader's endpoint address and a short-lived, server-authenticated **match admission ticket** to authorized room members.
5. A guest connects to the leader using the versioned match ALPN. Iroh authenticates the remote EndpointId at the transport layer.
6. The host validates the server-issued ticket and verifies that its player, room, match epoch, role, expiry and endpoint identity match the authoritative room membership.
7. The peers open the unreliable datagram lane and reliable event/control streams.
8. The host runs the match core. The Game server continues to own the authoritative room lifecycle and the outcomes that the reference assigns to it.
9. On disconnect, the client attempts the defined reconnect/resume flow; the Game server remains the source of truth for membership and match epoch.

The match admission ticket must be distinct from an account bearer token. Do not expose account tokens or reuse the existing Game enterTicket without a separate protocol/security review. The proposed match ticket should be signed by the server and bind at least:

- Player ID.
- Room ID and match ID.
- Current match epoch.
- Expected Iroh EndpointId.
- Role/player slot and permitted capabilities.
- Expiry and unique nonce.

The host must reject expired, replayed, wrong-room, wrong-epoch and wrong-endpoint tickets. A peer must not gain authority merely by knowing another player's EndpointId.

## 6. LAN match flow

For LAN-first discovery:

1. The client starts its Iroh Endpoint with local address lookup enabled.
2. It advertises or discovers compatible Point Blank match endpoints through mDNS.
3. A LAN lobby layer filters announcements by game/protocol version, room visibility and match state.
4. The user joins a discovered room or enters an invite code/address manually.
5. The client establishes a direct Iroh connection over the local subnet and validates the match admission ticket or the explicitly selected offline-LAN policy.
6. Match traffic uses the same datagram/stream mapping as online play.

For fully offline play, a designated local host or LAN dedicated server must own room membership, host selection, match epoch, match rules and result policy. The implementation must clearly distinguish trusted local-host mode from online account-backed mode; it must not silently treat an unauthenticated LAN peer as a trusted Game server.

## 7. Host authority, handoff and recovery

Iroh does not provide Point Blank host election, match-state replication or authoritative game rules. These remain application responsibilities.

Preserve the reference authority split:

- **Game server:** room membership, leader selection, respawns, deaths, round/match lifecycle, score, EXP and currency.
- **Match host:** real-time match core and the mode-specific calculations that the reference delegates to the host.
- **Clients:** input and presentation; never trusted as authoritative merely because their Iroh connection is authenticated.

For planned handoff:
1. The Game server chooses the new leader and increments the match epoch.
2. The old host transfers a bounded, versioned state snapshot over a reliable stream.
3. The new host validates snapshot version, room, epoch, sequence/tick and sender authorization.
4. The Game server commits the new host and epoch.
5. Peers reconnect or switch their match connection to the new EndpointId.
6. The old host is fenced out by the epoch check.

For an unexpected host crash, the Game server selects a replacement and applies an explicit recovery policy. Iroh cannot recover volatile state that was never replicated. The reference WebPort's current fallback behavior must remain documented unless a deliberate, tested recovery improvement is implemented.

Do not allow two hosts to remain authoritative simultaneously. Every event and snapshot must be associated with the current match epoch, and stale-host messages must be rejected.

## 8. Security and abuse considerations

Iroh's encrypted transport and authenticated EndpointId are useful security primitives, but they do not replace Point Blank application authorization or anti-cheat validation.

Required controls:
- Bind EndpointId to the authenticated player and match using a server-signed, short-lived ticket.
- Validate room membership, role, match epoch and ticket expiry on every new peer session.
- Prevent ticket replay and stale-host/split-brain operation.
- Keep account tokens, password material and database credentials out of peer traffic.
- Rate-limit connection attempts, stream creation, datagram processing and expensive gameplay validation.
- Bound packet sizes, stream frame sizes, queue lengths and snapshot sizes.
- Treat every peer payload as untrusted, even on an encrypted connection.
- Preserve server-side validation for kills, deaths, scores, EXP, currency and match lifecycle.
- Decide whether EndpointIds are stable for the process or rotated between launches; avoid publishing a long-lived player identity unnecessarily.
- Consider relay metadata and IP-address exposure. Direct P2P connections reveal network addresses to peers; relay use has a different privacy and operational profile.

## 9. Browser compatibility and transport abstraction

The current WebPort is a browser client using WebRTC. The Rust PointBlank port may have native targets, but a native Iroh implementation is not automatically a browser-compatible replacement for WebRTC.

Recommended multi-transport design:

~~~text
                 pb-match core
                      |
             MatchTransport contract
                 /           \
                /             \
       WebRTC backend       Iroh backend
       browser client       native Rust client
                \             /
                 \           /
               pb-protocol payloads
~~~

The abstraction should express application operations (send unreliable payload, send reliable event, receive, close, peer identity/metadata) rather than leak WebRTC or Iroh types into the match core.

Keep the WebRTC backend for browser clients until a separate browser/WASM feasibility study proves that Iroh can meet the browser's networking, API and deployment constraints. Do not assume native socket behavior, mDNS access or relay configuration is available in a browser sandbox.

Do not add an Iroh dependency to **pb-server-transport**. That crate owns the existing TCP server transport. The first Iroh experiment should live in an isolated future match-transport crate or feature, not in **pb-protocol**.

## 10. Comparison with current and alternative transports

| Capability | WebRTC DataChannels | Iroh / QUIC | Raw UDP |
|---|---|---|---|
| Browser support | Native browser API | Not a drop-in browser API | Not directly available to ordinary browser JS |
| Direct peer connectivity | ICE/STUN/TURN | Hole punching + relay fallback | Requires custom NAT traversal/relay |
| Encrypted peer transport | DTLS | QUIC/TLS with endpoint identity | Must be designed separately |
| Unreliable lane | Unordered/unreliable DataChannel | QUIC application datagrams | Native datagrams |
| Reliable lane | Reliable DataChannel | QUIC streams | Must be built separately |
| LAN discovery | Requires separate discovery | mDNS companion crate / other lookup | Requires separate discovery |
| Native Rust integration | Possible through WebRTC stacks | Native Rust library | Native OS sockets |
| Existing WebPort compatibility | Current reference transport | Requires new backend and validation | Existing UDP codec is already being ported |

Iroh's strongest advantage is an integrated native Rust P2P connection and discovery stack, not a promise of lower latency than raw UDP. QUIC adds encryption, transport state and congestion control; relay paths add an extra hop. Compare measured end-to-end results rather than assuming that a newer transport is faster.

## 11. Proposed prototype and acceptance tests

Do not begin with a full match migration. Build a small transport spike with two native processes and a fake match payload.

### Phase A: connectivity

- Two local processes connect by direct local address.
- Two LAN machines discover one another through mDNS and connect with no Internet uplink.
- LAN discovery failure is reported cleanly when multicast is blocked.
- Two machines on separate home networks connect directly when NAT traversal succeeds.
- Two machines behind restrictive NAT/CGNAT connect through relay fallback.
- A custom/self-hosted relay can be configured and measured.
- Relay unavailability and address-lookup failure produce bounded, actionable errors.

### Phase B: traffic semantics

- Send unreliable position/action payloads as QUIC datagrams.
- Verify loss, reordering, stale-sequence rejection and bounded queue behavior.
- Query and respect max_datagram_size; test payloads near and beyond the negotiated limit.
- Send reliable events over streams with explicit framing and sequence IDs.
- Prove independent streams do not cause application-level blocking between event and snapshot traffic.
- Test reconnect, duplicate event suppression and stream closure.

### Phase C: Point Blank integration fixtures

- Carry existing Point Blank Match payload bytes without changing the inner codec representation.
- Compare decoded messages with pb-protocol golden vectors.
- Test representative position/action, hit, grenade, weapon-drop and mission-event traffic.
- Test 8v8-like traffic volume and realistic burst patterns.
- Measure RTT, p50/p95/p99 latency, jitter, loss, bandwidth, CPU and memory.
- Compare direct LAN, direct WAN and relay paths against the WebRTC reference.

### Phase D: authority and recovery

- Reject invalid, expired, replayed and wrong-endpoint match tickets.
- Reject peers not in authoritative room membership.
- Reject stale match epochs and old-host messages after handoff.
- Transfer a versioned state snapshot over a reliable stream.
- Kill the host process unexpectedly and validate the documented recovery policy.
- Confirm peer transport never grants authority over server-owned room, score or progression state.

### Acceptance gate

An Iroh backend is eligible for integration only when:
1. The same native match fixtures pass over WebRTC and Iroh backends.
2. LAN discovery works without Internet access on supported desktop targets.
3. WAN connectivity succeeds directly where possible and via relay where necessary.
4. Datagram limits and loss/reordering behavior are handled explicitly.
5. Host handoff and stale-host fencing are tested.
6. Performance measurements are recorded against the current reference.
7. The browser WebRTC path and existing TCP/Auth path remain unaffected.

## 12. Recommendation and implementation sequence

**Recommendation: proceed with an isolated native Iroh prototype, not a transport replacement.**

Suggested sequence:

1. Keep this document as the architecture baseline.
2. Add a minimal native connectivity spike using the current Iroh 1.5.x API line, with versions pinned in the experiment.
3. Validate local direct connectivity and mDNS LAN discovery first.
4. Validate WAN direct connectivity and relay fallback next.
5. Implement a small MatchTransport contract and Iroh backend only after connectivity tests pass.
6. Carry existing match payload bytes through QUIC datagrams and streams, preserving pb-protocol golden tests.
7. Add server-signed match admission tickets, match epochs and host handoff.
8. Benchmark Iroh against the WebRTC reference before selecting it as the native default.
9. Keep WebRTC for the browser client unless a separate browser compatibility study proves otherwise.

**Not in scope for this PR:** adding Iroh dependencies, creating a production relay, implementing the transport adapter, modifying UDP 121/CMess packet formats, changing Game authority, or removing WebRTC.

## 13. References

### Point Blank reference

- [Point Blank WebPort README: online play and peer-hosted matches](https://github.com/LeandroDettmer/point-blank-webport#game-modes-and-online-play)
- [PointBlankRust porting plan](PORTING_PLAN.md)
- [PointBlankRust Rust Gaming Eclipse contract](RUST-GAMING-ECLIPSE.md)

### Iroh 1.5.0 documentation

- [Iroh 1.5.0 crate documentation](https://docs.rs/iroh/1.5.0/iroh/)
- [Iroh 1.5.0 release and architecture overview](https://docs.rs/crate/iroh/1.5.0)
- [Endpoint and connection APIs](https://docs.rs/iroh/1.5.0/iroh/endpoint/struct.Connection.html)
- [Endpoint builder and relay configuration](https://docs.rs/iroh/1.5.0/iroh/endpoint/struct.Builder.html)
- [Endpoint address structure](https://docs.rs/iroh/1.5.0/iroh/struct.EndpointAddr.html)
- [iroh-mdns-address-lookup](https://docs.rs/iroh-mdns-address-lookup/latest/iroh_mdns_address_lookup/)

Iroh evolves quickly. Re-check selected crate versions, feature flags, target support and exact API signatures when the prototype begins. This document records architectural findings, not a frozen implementation recipe.
