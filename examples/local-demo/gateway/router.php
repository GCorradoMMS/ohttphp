<?php

declare(strict_types=1);

/**
 * Local Oblivious Gateway Resource (development demo only).
 *
 *   POST /oblivious/request -> OhttpGatewayHandler (RFC 9458 gateway role)
 *   GET  /ohttp-keys        -> GatewayKeyConfigHandler (application/ohttp-keys)
 *
 * The target policy is explicitly development-only: it permits HTTP to
 * 127.0.0.1:8003 (the local target) only. Do not copy this configuration
 * to production.
 */

require __DIR__ . '/../lib/HttpKernel.php';

use Gcorradomms\Ohttphp\Gateway\FileGatewayKeyStore;
use Gcorradomms\Ohttphp\Gateway\GatewayKeyConfigHandler;
use Gcorradomms\Ohttphp\Gateway\OhttpGatewayHandler;
use Gcorradomms\Ohttphp\Gateway\Target\AllowlistTargetPolicy;

$keyStore = new FileGatewayKeyStore(__DIR__ . '/../var/keys');
$factories = HttpKernel::factories();

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

switch ($path) {
    case '/oblivious/request':
        HttpKernel::run(new OhttpGatewayHandler(
            $keyStore,
            // Development-only policy: local loopback target on port 8003.
            AllowlistTargetPolicy::forLocalDevelopment(['127.0.0.1'], [8003]),
            HttpKernel::httpClient(),
            $factories,
            $factories,
            $factories,
            $factories,
        ));
        break;

    case '/ohttp-keys':
        HttpKernel::run(new GatewayKeyConfigHandler($keyStore, $factories, $factories));
        break;

    default:
        http_response_code(404);
        header('Content-Type: application/json');
        echo json_encode(['title' => 'Not found'], JSON_UNESCAPED_SLASHES);
        break;
}