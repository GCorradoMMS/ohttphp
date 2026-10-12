<?php

declare(strict_types=1);

require __DIR__ . '/../../../vendor/autoload.php';

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Adapter that runs a PSR-15 request handler under PHP's built-in web
 * server (or any SAPI) by converting the superglobals to a PSR-7 server
 * request and emitting the returned response.
 *
 * This adapter is for the local demo only; real deployments should run
 * PSR-15 handlers through a framework or a production-grade emitter.
 */
final class HttpKernel
{
    public static function run(RequestHandlerInterface $handler): void
    {
        $factories = new Psr17Factory();
        $creator = new ServerRequestCreator($factories, $factories, $factories, $factories);
        $serverRequest = $creator->fromGlobals();

        $response = $handler->handle($serverRequest);

        self::emit($response);
    }

    public static function emit(ResponseInterface $response): void
    {
        http_response_code($response->getStatusCode());
        foreach ($response->getHeaders() as $name => $values) {
            foreach ($values as $value) {
                header($name . ': ' . $value, false);
            }
        }
        echo (string) $response->getBody();
    }

    /**
     * Shared factory for demo HTTP clients. Redirects are never followed
     * (the gateway must return redirect responses to the client rather
     * than following them), with conservative timeouts.
     */
    public static function httpClient(): \GuzzleHttp\Client
    {
        return new \GuzzleHttp\Client([
            'allow_redirects' => false,
            'connect_timeout' => 3,
            'timeout' => 10,
            'http_errors' => false,
        ]);
    }

    public static function factories(): Psr17Factory
    {
        return new Psr17Factory();
    }
}