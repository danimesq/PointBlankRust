# Auth Service

The `pb-auth-service` crate implements the business-policy portion of the WebPort
Auth server's `handleLogin()` flow. It is deliberately independent of a specific
SQL driver, TCP runtime, and Game Server implementation.

## Login flow

1. Apply the per-IP one-second duplicate-login throttle.
2. Resolve the client-supplied Base64 token through `AuthRepository::lookup_token`.
3. Validate username/password-size policy, nonzero MAC, client version, optional
   user-file-list equality, and nonzero resolution.
4. Check active account bans and permanent/automatic account bans.
5. Persist the presented MAC and check MAC/IP bans.
6. Apply the Auth-side access-level / ChannelOnlyGM policy.
7. Detect an already-online account and delegate the existing-session kick path.
8. Check the account's stored ban-object expiry.
9. Load successful-login account metadata and mint the Game enter ticket.
10. Atomically claim online ownership, then emit LOGIN_ACK plus GET_POINT_CASH_ACK. Minting first prevents a signer failure from stranding the account online.

## Host integration contract

The host implements `AuthRepository` using its database and session runtime.
Important requirements:

- Token lookup receives the Base64 representation of the raw token bytes from
  LOGIN. It must hash the credential exactly as the WebPort does:
  `h:` + the first 30 Base64URL characters of SHA-256(token). A stored hash
  must never itself be accepted as a login credential. Legacy plaintext rows
  may be lazily migrated.
- Active account-ban lookup ignores MUTE rows and considers only unexpired bans
  where owner_id or player_id matches the account.
- Permanent-ban lookup mirrors Account.IsBanned: access=-1, any auto-ban, or
  any non-MUTE ban-history row for the owner, including expired rows.
- MAC ban lookup uses uppercase hexadecimal without separators; the stored
  account MAC uses lowercase hexadecimal separated by colons. IP bans use the
  peer IP and only unexpired IP4 rows.
- `claim_login` must be a database-atomic compare-and-set. It writes
  `accounts.mac_address`, `accounts.status=0xff00ffff`, and `accounts.online=true`
  only if the account is still offline. A read-then-write implementation is
  not sufficient because concurrent login attempts can race.
- `handle_existing_login` mirrors the existing WebPort behavior: an Auth-local
  session is kicked directly; a Game-owned account is handed off to the Game
  session manager; a stale Auth/unknown server status is marked offline.
- `mint_enter_ticket` must use the same signed, expiring ticket format and
  secret as the Game USER_ENTER validator. Do not substitute a random string.
- The returned enter ticket is an out-of-band WebSocket text frame, not a
  Point Blank binary packet.

## Shared cryptographic primitives

The workspace also contains `pb-auth-security`, which implements the exact
WebPort credential and enter-ticket formats:

- `stored_token(token)` produces `h:` plus the first 30 Base64URL characters
  of SHA-256 over the Base64 token string. It rejects empty values and values
  already carrying the stored-hash prefix.
- `EnterTicketSigner` creates the WebPort enter-ticket body
  `enter.<player_id>.<expiry_unix_seconds>`, Base64URL-encodes it, and signs
  the encoded body with HMAC-SHA256. The default lifetime is 12 hours.
- Verification checks the HMAC in constant time, validates the claim shape,
  and rejects expired tickets.

The signer deliberately accepts a 32-byte secret from the host. Auth and Game
must load the same secret. The TypeScript reference generates one random secret
per process and shares it between Auth and Game modules in that process; two
independent Rust processes must instead receive the same configured secret.
The crate does not silently generate a key, persist one, or invent a fallback.

## PostgreSQL adapter

The `pb-auth-postgres` crate implements `AuthRepository` against the schema
in the WebPort's `db/init/001_init.sql` and the queries in `server/src/db.ts`.
It includes:

- Indexed token lookup by the WebPort hash, with conditional lazy migration
  from legacy plaintext tokens.
- Active and permanent account-ban queries, including the MUTE exclusion.
- MAC/IP ban checks and account MAC persistence.
- Account ban-object expiry lookup.
- Atomic online ownership via one conditional UPDATE from offline to online,
  setting `mac_address` and `status=0xff00ffff` in the same statement.
- Enter-ticket minting through the shared `EnterTicketSigner`.

The host passes an already-connected PostgreSQL `Client`, so it controls
connection parameters and TLS. This first adapter serializes access through
one connection; it is a functional integration boundary, not a production
connection pool. `AuthSessionBridge` remains host-provided because the live
Auth/Game session registry and account metadata loader are process/runtime
concerns, not SQL concerns.

## Protocol behavior

The service uses the reference LOGIN response codes and packet builders already
ported into `pb-auth`. Invalid token, invalid client payload, account/MAC/IP
bans, access denial, and duplicate online account intentionally have different
responses and close modes matching the WebPort flow.

The service returns packets in send order and reports whether the connection
must stay open, close softly, or be destroyed. The TCP/WebSocket host remains
responsible for applying those effects and for cleaning up online state on a
destroying disconnect.

## Scope boundary

The crate does not open database connections or listen on sockets. That is an
intentional adapter boundary, not a fake in-memory database. The next integration
slice wires a concrete Postgres repository and the existing Game session/ticket
bridge into the Auth packet dispatcher.
