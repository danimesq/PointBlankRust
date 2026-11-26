# Auth runtime integration

## Runtime composition

The workspace now has a concrete TCP Auth handler in `pb-auth-runtime`. The host supplies the PostgreSQL connection, an `AuthSessionBridge`, LOGIN policy settings and an optional WebSocket text-frame sink.

The dependency direction is:

~~~text
pb-server-transport
        |
pb-auth-runtime
   /    |     \
pb-auth pb-auth-service
              /      \
      pb-auth-security  pb-auth-postgres
~~~

## What happens on a TCP connection

1. The transport accepts the socket and calls `TcpSessionHandler::on_connect`.
2. The runtime allocates a protocol session ID in the supported 1..32767 range.
3. It generates the reference-compatible CONNECT_ACK key material and sends opcode 2306 using the transport's plaintext PB server-frame writer.
4. Each incoming encrypted frame is passed through CMess MODE_AUTH, the Auth first-packet allowlist and the session-seed LCG window.
5. Typed packets are routed through `dispatch_auth_packet`. LOGIN is decoded and passed to `AuthService`.
6. Successful LOGIN emits a separate JSON WebSocket TEXT message for `enterTicket` when enabled, followed by LOGIN_ACK and GET_POINT_CASH_ACK as ordinary PB server frames.
7. A destructive disconnect releases the authenticated account's online/status claim. USER_LEAVE is treated as a handoff and preserves that claim.

## PostgreSQL host setup

The host creates one shared 32-byte ticket secret and passes the same bytes to Auth and Game. It creates an `EnterTicketSigner`, a `PgAuthRepository` and the runtime handler. The PostgreSQL `Client` is supplied by the host so TLS and connection configuration remain host-owned.

The host must implement `AuthSessionBridge` for live Auth/Game session kicks and successful-login account metadata loading. This is not a database-only operation.

## WebSocket enterTicket contract

The reference WebPort sends this message as a WebSocket TEXT frame before the binary PB LOGIN_ACK and CASH_ACK frames:

~~~json
{"t":"enterTicket","pid":"126","ticket":"<signed-ticket>"}
~~~

The runtime serializes this as JSON and routes it through `AuthTextFrameSink`. It never appends the JSON bytes to a PB packet or binary TCP frame.

Important transport boundary: `pb-server-transport` currently implements raw TCP. Raw TCP sessions do not have WebSocket TEXT frames, so `send_enter_ticket` defaults to false and the no-op sink deliberately returns Unsupported. A WebSocket host must implement the sink by writing a real text message on the same logical WebSocket session, and enable ticket delivery only after that adapter is connected. If the sink fails, the login output fails and the connection is closed; the runtime does not silently pretend the ticket was delivered.

## Current scope and remaining work

This integration wires CONNECT_ACK, CMess ingress, seed validation, LOGIN dispatch, LOGIN_ACK/CASH_ACK output, session ownership cleanup and the WebSocket ticket output contract.

The remaining Auth opcode handlers (server state, channel list, account metadata, inventory/options and complete Game handoff operations) are intentionally not stubbed as successful implementations. They remain explicit follow-up work before the Auth runtime is a complete replacement for the WebPort Auth server.

The PostgreSQL adapter still serializes access through one connection. A production host should supply a properly configured TLS connection and evaluate a pool-backed executor under load.
