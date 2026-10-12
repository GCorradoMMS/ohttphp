# ohttphp local end-to-end demo

A complete, self-contained Oblivious HTTP environment on `127.0.0.1`:

- **target** on `127.0.0.1:8003` — a deterministic HTTP resource
- **gateway** on `127.0.0.1:8002` — the production `OhttpGatewayHandler`
  and `GatewayKeyConfigHandler` from the library
- **relay** on `127.0.0.1:8001` — the production `OhttpRelayHandler`
- **client** (`client.php`) — the production `OhttpClient`

All three hops use real HPKE cryptography via `paragonie/hpke`; nothing
is mocked. The relay only sees opaque `message/ohttp-req` /
`message/ohttp-res` payloads.

## Requirements

- PHP 8.2+ with the `gmp` and `openssl` extensions
- `composer install` in the repository root (Guzzle is used by the demo
  as the PSR-18 transport; the library itself stays transport-agnostic)

## Commands

```bash
# 1. Initialize the gateway key store (skips if keys exist)
./init.sh

# 2. Start target, gateway, and relay
./start.sh

# 3. Run the client scenarios (in another shell or right after start)
php client.php

# 4. Stop the servers
./stop.sh
```

To reset the environment completely:

```bash
./stop.sh
rm -rf var
./init.sh
```

## Scenarios exercised by client.php

1. `GET /hello?name=Oblivious` — query string travels inside the
   encrypted request; target answers 200.
2. `POST /echo` — a request body and content type, protected end to end.
3. `GET /not-found` — the target's 404 is returned through OHTTP.
4. `GET /error` — the target's 500 is returned through OHTTP.
5. Blocked target — the client requests `http://127.0.0.1:9999/private`;
   the gateway's target policy (which only permits `127.0.0.1:8003`)
   rejects it. The rejection is **encapsulated**, so the relay observes
   an ordinary 200 `message/ohttp-res` while the client decrypts a 403.

## Configuration notes

- Gateway keys live in `var/keys` (mode 0700 directory, 0600 files) and
  are managed with `bin/ohttphp-gateway-keys`.
- The gateway target policy is `AllowlistTargetPolicy::forLocalDevelopment()`
  — a **development-only** opt-in that permits plain HTTP to loopback.
  Never enable it in production.
- The relay's gateway URI is hard-wired to
  `http://127.0.0.1:8002/oblivious/request` and cannot be influenced by
  requests; no client header is forwarded upstream.

## Trust boundaries in this demo

- The relay sees your network connection, not the request contents.
- The gateway decrypts requests and sees the target URL and response.
- The target sees requests from the gateway.

Because the relay and gateway run on the same operator's machine here,
this demo does not provide protection against that operator correlating
clients with requests — in production they must be operated separately.
The built-in PHP development server is for demonstration only; production
deployments need TLS, hardened servers, monitoring, and network egress
controls.