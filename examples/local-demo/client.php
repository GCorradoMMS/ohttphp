<?php

declare(strict_types=1);

/**
 * Client demo: performs real Oblivious HTTP exchanges through the local
 * relay and gateway against the local target.
 *
 * Prerequisites: ./init.sh, then ./start.sh (see README.md).
 */

require __DIR__ . '/lib/HttpKernel.php';

use Gcorradomms\Ohttphp\KeyConfig\KeyConfigCollection;
use Gcorradomms\Ohttphp\OhttpClient;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Request;

const GATEWAY_KEYS_URL = 'http://127.0.0.1:8002/ohttp-keys';
const RELAY_URI = 'http://127.0.0.1:8001/';
const TARGET_ORIGIN = 'http://127.0.0.1:8003';

function run_scenario(string $name, Request $request, OhttpClient $client, KeyConfigCollection $keys): bool
{
    try {
        $response = $client->send($request, $keys, RELAY_URI);
    } catch (Throwable $e) {
        printf("FAIL %-28s %s: %s\n", $name, get_class($e), $e->getMessage());

        return false;
    }

    $body = (string) $response->getBody();
    printf(
        "OK   %-28s status=%d body=%s\n",
        $name,
        $response->getStatusCode(),
        substr(str_replace("\n", ' ', $body), 0, 96)
    );

    return true;
}

$http = HttpKernel::httpClient();
$factories = new Psr17Factory();

// 1. Obtain the gateway key configuration over the authenticated (local)
//    configuration endpoint.
$keysResponse = $http->get(GATEWAY_KEYS_URL);
if ($keysResponse->getStatusCode() !== 200) {
    fwrite(STDERR, 'error: could not fetch gateway key configuration (' . $keysResponse->getStatusCode() . ")\n");
    exit(1);
}
$keys = KeyConfigCollection::fromEncoded((string) $keysResponse->getBody());
printf(
    "fetched %d gateway key configuration(s) from %s\n",
    count($keys),
    GATEWAY_KEYS_URL
);

// 2. Build the real OHTTP client and run the scenarios end to end.
$client = new OhttpClient($http, $factories, $factories, $factories, $factories);

$passed = 0;
$total = 0;

$total++; $passed += (int) run_scenario(
    'GET /hello (query string)',
    new Request('GET', TARGET_ORIGIN . '/hello?name=Oblivious'),
    $client,
    $keys
);

$total++; $passed += (int) run_scenario(
    'POST /echo (body)',
    new Request(
        'POST',
        TARGET_ORIGIN . '/echo',
        ['Content-Type' => 'text/plain'],
        'request body protected end to end'
    ),
    $client,
    $keys
);

$total++; $passed += (int) run_scenario(
    'GET /not-found (404)',
    new Request('GET', TARGET_ORIGIN . '/not-found'),
    $client,
    $keys
);

$total++; $passed += (int) run_scenario(
    'GET /error (500)',
    new Request('GET', TARGET_ORIGIN . '/error'),
    $client,
    $keys
);

// Blocked target: the gateway policy only permits 127.0.0.1:8003. The
// violation is returned as an encapsulated response, so the client sees
// a 403 while the relay learns nothing.
$total++; $passed += (int) run_scenario(
    'blocked target (403)',
    new Request('GET', 'http://127.0.0.1:9999/private'),
    $client,
    $keys
);

printf("\n%d/%d scenarios passed\n", $passed, $total);

exit($passed === $total ? 0 : 1);