<?php

declare(strict_types=1);

/**
 * Local Oblivious Relay Resource (development demo only).
 *
 * All paths are treated as the relay endpoint; the gateway URI is fixed
 * by the operator below and cannot be influenced by requests.
 */

require __DIR__ . '/../lib/HttpKernel.php';

use Gcorradomms\Ohttphp\Relay\OhttpRelayHandler;

HttpKernel::run(new OhttpRelayHandler(
    'http://127.0.0.1:8002/oblivious/request',
    HttpKernel::httpClient(),
    HttpKernel::factories(),
    HttpKernel::factories(),
    HttpKernel::factories(),
));