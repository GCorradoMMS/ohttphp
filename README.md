# ohttphp

[![CI](https://github.com/gcorradomms/ohttphp/actions/workflows/ci.yml/badge.svg)](https://github.com/gcorradomms/ohttphp/actions/workflows/ci.yml)

A PHP implementation of [Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
(RFC 9458) covering all three protocol roles:

- **Client** - sends HTTP requests to a target through an Oblivious Relay
  Resource so that the relay learns neither the request contents nor the
  target identity, and the Oblivious Gateway Resource learns only the
  relay, not the client.
- **Relay** - forwards opaque encapsulated requests to a fixed gateway and
  returns its responses without decrypting or inspecting anything.
- **Gateway** - decapsulates requests, forwards the decoded HTTP request
  to the target resource under an explicit access policy, and returns the
  target's response in an Encapsulated Response.

Request and response protection is built on
[HPKE](https://www.rfc-editor.org/rfc/rfc9180.html) (RFC 9180) and
[Binary HTTP](https://www.rfc-editor.org/rfc/rfc9292.html) (RFC 9292).
Cryptographic primitives are delegated to
[paragonie/hpke](https://github.com/paragonie/hpke-php); nothing is
implemented from scratch.

## Requirements

- PHP 8.2 or newer
- The `gmp` and `openssl` extensions

## Installation

```terminal
composer require gcorradomms/ohttphp
```

## The three trust roles

- The **relay** sees the client's network connection. It must never see
  the protected request; this library's relay forwards only opaque bytes
  and copies no client headers upstream.
- The **gateway** decrypts requests, so it sees the target URL and
  request contents by design. It should not receive identifying client
  network metadata; the library's relay never sends it.
- The **target** receives the HTTP request from the gateway, not from the
  client.

OHTTP protects the link between the **client and the gateway**. It does
not provide end-to-end confidentiality between the client and the target
resource: the gateway can read everything. Use HTTPS for target
transport when the request contents deserve protection from the gateway
as well. If the relay and the gateway are operated by the same party,
that party can correlate client identities with request contents -
meaningful privacy requires independently operated relay and gateway.

## Supported HPKE suites

| KEM                        | KDF         | AEAD              |
|----------------------------|-------------|-------------------|
| DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | AES-128-GCM       |
| DHKEM(P-256, HKDF-SHA256)  | HKDF-SHA384 | AES-256-GCM       |
| DHKEM(P-384, HKDF-SHA256)  | HKDF-SHA512 | ChaCha20Poly1305  |
| DHKEM(P-521, HKDF-SHA512)  |             |                   |

Any KEM may be combined with any KDF/AEAD pair advertised by the
gateway. Suites the library does not implement are skipped during
selection and rejected by the gateway when not advertised.

## Client usage

The client takes a PSR-18 HTTP client (for talking to the relay) and
PSR-17 factories:

```php
use Gcorradomms\Ohttphp\KeyConfig\KeyConfigCollection;
use Gcorradomms\Ohttphp\OhttpClient;
use GuzzleHttp\Client as GuzzleClient;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Request;

$factory = new Psr17Factory();

$client = new OhttpClient(
    httpClient: new GuzzleClient(['allow_redirects' => false]),
    requestFactory: $factory,
    streamFactory: $factory,
    responseFactory: $factory,
    uriFactory: $factory,
);

// Key configurations of the gateway, obtained over an authenticated
// channel (RFC 9458, Section 3). Accepts a single configuration or an
// "application/ohttp-keys" collection.
$keyConfigs = KeyConfigCollection::fromEncoded($keyConfigBytes);

$response = $client->send(
    new Request('GET', 'https://target.example.net/hello'),
    $keyConfigs,
    'https://relay.example.org/proxy'   // Oblivious Relay Resource URI
);
```

For step-by-step exchanges, `encapsulate()` returns the context needed to
decrypt the response later:

```php
$encapsulation = $client->encapsulate($request, $keyConfigs);
// ... POST $encapsulation->encapsulatedRequest to the relay yourself ...
$response = $client->decapsulateResponse($encapsulation->context, $relayBody);
```

Per RFC 9458 Section 6.5.1, a `Date` header is added to encapsulated
requests when the target request does not already carry one.

## Relay integration

`OhttpRelayHandler` is a PSR-15 handler. It requires POST with
`Content-Type: message/ohttp-req`, enforces a configurable body size
limit, and forwards the payload byte for byte to a fixed gateway URI.
It copies **no** client headers to the gateway - nothing identifying
(`Forwarded`, `X-Forwarded-For`, `User-Agent`, cookies, credentials, ...)
crosses the privacy boundary - and forwards gateway responses with only
their content type, never leaking upstream metadata.

```php
use Gcorradomms\Ohttphp\Relay\OhttpRelayHandler;
use Psr\Log\LoggerInterface;

$relay = new OhttpRelayHandler(
    gatewayUri: 'https://gateway.internal.example/oblivious/request',
    httpClient: $psr18Client,          // transport toward the gateway
    requestFactory: $requestFactory,
    responseFactory: $responseFactory,
    streamFactory: $streamFactory,
    maxEncapsulatedRequestSize: 65536, // optional
    staticUpstreamHeaders: [],         // operator-configured only
    logger: $logger,                   // optional PSR-3, redacted
);

// Slim: $app->post('/relay', $relay);
// or generic middleware stack: $relay->handle($serverRequest);
```

Transport failures are mapped to generic 502/504 problem responses
without internal details. Timeouts belong to the PSR-18 client's
configuration (for example Guzzle's `timeout` and `connect_timeout`
options); set `allow_redirects => false` on the gateway hop as well.

## Gateway integration

### Key generation and rotation

Gateway keys are managed as key pairs: an 8-bit key identifier, a KEM,
the HPKE private key, the advertised KDF/AEAD suites, and lifecycle
metadata. The public key is always derived from the private key.

```php
use Gcorradomms\Ohttphp\Gateway\FileGatewayKeyStore;
use Gcorradomms\Ohttphp\Gateway\GatewayKeyPair;
use Gcorradomms\Ohttphp\Gateway\InMemoryGatewayKeyStore;
use Gcorradomms\Ohttphp\KeyConfig\{AeadId, KemId, KdfId, SymmetricSuite};

$suites = [
    SymmetricSuite::from(KdfId::HkdfSha256, AeadId::Aes128Gcm),
    SymmetricSuite::from(KdfId::HkdfSha256, AeadId::ChaCha20Poly1305),
];

// In-memory (tests, ephemeral deployments):
$store = new InMemoryGatewayKeyStore();

// File-based (simple installations and the local demo):
$store = new FileGatewayKeyStore('/var/lib/ohttphp/keys'); // 0700 dir, 0600 files

$keyPair = GatewayKeyPair::generate(1, KemId::DhkemX25519HkdfSha256, $suites);
$store->add($keyPair);

// Rotation: advertise a new key, keep the old one decryptable.
$newPair = GatewayKeyPair::generate(2, KemId::DhkemX25519HkdfSha256, $suites);
$store->add($newPair);
$store->retire(1); // still decrypts clients holding the old configuration,
                   // but is no longer advertised. Keep retired keys until
                   // clients have had time to refresh their configuration.
```

Or from the command line (secret material is never printed):

```bash
php bin/ohttphp-gateway-keys generate --store /var/lib/ohttphp/keys
php bin/ohttphp-gateway-keys list    --store /var/lib/ohttphp/keys
php bin/ohttphp-gateway-keys show    --store /var/lib/ohttphp/keys --key-id 1
php bin/ohttphp-gateway-keys retire  --store /var/lib/ohttphp/keys --key-id 1
```

The file store validates stored material (structure, KEM consistency,
public/private agreement), writes atomically, and handles missing or
corrupted files by failing closed. It is **not** a substitute for a
secrets manager or hardware-backed key management: implement
`GatewayKeyStoreInterface` to integrate one.

### Serving the key configuration

`GatewayKeyConfigHandler` publishes the active public key
configurations in the exact `application/ohttp-keys` binary format of
RFC 9458 Section 3. It contains public material only; retired keys are
excluded. The endpoint path is a deployment choice, not standardized.

```php
use Gcorradomms\Ohttphp\Gateway\GatewayKeyConfigHandler;

$keysHandler = new GatewayKeyConfigHandler($store, $responseFactory, $streamFactory);
// Slim: $app->get('/ohttp-keys', $keysHandler);
```

Distribute configurations over an authenticated, integrity-protected
channel (normally HTTPS). Publishing public key material over plain HTTP
is not secure.

### The gateway handler

`OhttpGatewayHandler` is a PSR-15 handler implementing the receiver side
of RFC 9458 Sections 4.3 and 4.4:

```php
use Gcorradomms\Ohttphp\Gateway\OhttpGatewayHandler;
use Gcorradomms\Ohttphp\Gateway\Target\AllowlistTargetPolicy;

$gateway = new OhttpGatewayHandler(
    keyStore: $store,
    targetPolicy: new AllowlistTargetPolicy(
        allowedHosts: ['api.example.net'],
        allowedSchemes: ['https'],
        allowedPorts: null,                       // any port for https
        allowPrivateAddresses: false,             // default; dev-only opt-in exists
        resolver: null,                           // defaults to PHP DNS
    ),
    targetClient: $psr18Client,       // transport toward target resources
    requestFactory: $requestFactory,
    responseFactory: $responseFactory,
    streamFactory: $streamFactory,
    uriFactory: $uriFactory,
    maxEncapsulatedRequestSize: 65536,
    maxTargetResponseBodySize: 1048576,
    logger: $logger,
);
```

Processing: validate method/content-type/size, parse the 7-byte OHTTP
header (key id, KEM, KDF, AEAD), resolve the private key by identifier,
verify the suite is advertised and supported, split the encapsulated KEM
key with strict bounds, open the request via HPKE, decode Binary HTTP,
enforce the target policy, forward to the target (hop-by-hop headers
stripped, redirects never followed), encode and encapsulate the response
with a cryptographically secure response nonce, and reply
`200 message/ohttp-res`.

**Error model.** Failures before decapsulation (unknown key, unsupported
suite, malformed or oversized payload, decryption failure) return uniform
plaintext `4xx` `application/problem+json` responses; decryption failures
are deliberately indistinguishable from other processing failures. After
decapsulation (policy violations -> 403, invalid Binary HTTP or
unsupported request forms -> 400, target network failure -> 502, target
timeout -> 504, oversized target response -> 502), errors are returned
**encapsulated**, so the relay observes an ordinary 200 while the client
decrypts a synthetic problem response. Logs (optional PSR-3) contain
status codes, key identifiers, and error classes only - never bodies,
URLs, or key material.

## Target resource security (SSRF prevention)

The gateway decrypts client-controlled URLs and then issues outbound
requests, which makes unrestricted gateways a proxy into private
networks. Access control is therefore a separate, default-deny
abstraction:

```php
use Gcorradomms\Ohttphp\Gateway\Target\AllowlistTargetPolicy;

$policy = new AllowlistTargetPolicy(
    allowedHosts: ['api.example.net'],   // exact, case-insensitive
    allowedSchemes: ['https'],
    allowedPorts: [443],                 // or null for any port
    allowPrivateAddresses: false,        // production default
);
```

The default policy rejects every URI whose host is not exactly
allowlisted, rejects credentials in URLs, restricts schemes and ports,
and resolves every host name (A and AAAA) to validate the addresses it
points at. Addresses in loopback, private (RFC 1918 and ULA),
carrier-grade NAT, link-local (including `169.254.169.254` cloud
metadata), multicast, reserved, and documentation ranges are prohibited
for IPv4 and IPv6 alike, including IPv4-mapped IPv6 and NAT64-embedded
IPv4. Unresolvable hosts fail closed.

`allowPrivateAddresses: true` exists **for local development only**
(there is a dedicated `AllowlistTargetPolicy::forLocalDevelopment()`
helper); never enable it in production.

**DNS rebinding.** Validation happens immediately before forwarding, but
a generic PSR-18 client performs its own resolution and cannot pin the
validated address. Operators must therefore also enforce egress
restrictions at the network level (firewall rules from the gateway host)
as defense in depth. If redirect handling is added in the future, each
redirect destination must pass the same policy; for now redirects are
returned to the client rather than followed.

## Local end-to-end demo

A complete, runnable environment (target + gateway + relay + client) on
`127.0.0.1` with real cryptography and no external requests:

```bash
cd examples/local-demo
./init.sh       # generate a gateway key pair
./start.sh      # start target (8003), gateway (8002), relay (8001)
php client.php  # run GET/POST/404/500/blocked-target scenarios
./stop.sh
```

See [examples/local-demo/README.md](examples/local-demo/README.md) for
details and the trust-boundary notes for this environment.

## What is implemented (and what is not)

Implemented per RFC 9458: client, relay, and gateway roles; key
configuration encoding, parsing, publishing, and lifecycle (Sections 3,
7); encapsulated requests and responses (Sections 4.3, 4.4); the
`application/ohttp-keys` media type; gateway error handling in the
spirit of Section 5; Date-based anti-replay support on the client side.

Implemented per RFC 9292: the **known-length** Binary HTTP message
formats (framing indicators 0 and 1), including truncation and zero
padding rules.

Not implemented / out of scope:

- Indeterminate-length Binary HTTP (framing indicators 2 and 3).
- Informational (1xx) responses; trailer sections are validated but
  dropped after decoding (PSR-7 has no trailer representation) and are
  never emitted by the encoder.
- CONNECT requests and asterisk-form request targets.
- Key management beyond the built-in stores: no automatic fetching,
  refresh, or background rotation of client configurations.
- Post-quantum KEMs (RFC 9458 defines none; the additional KEMs
  paragonie/hpke supports are not exposed).
- Replay protection beyond the RFC's Date recommendation; deploying a
  gateway that tracks request `enc` values within a window remains an
  operator concern.

## Development

```terminal
composer install
composer test       # run the test suite
composer analyse    # run PHPStan at level max
```

The test suite includes the complete RFC 9458 Appendix A example as an
interoperability vector for both the client and gateway sides
(byte-exact, with deterministic ephemeral keys), full client-gateway
round trips for every supported ciphersuite combination, and dedicated
relay and gateway handler suites.

## License

MIT. See [LICENSE](LICENSE).
