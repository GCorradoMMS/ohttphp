<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Tests;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * PSR-18 client test double that records forwarded requests and produces
 * responses (or throws) from a callback.
 */
final class CallbackHttpClient implements ClientInterface
{
    /** @var list<RequestInterface> */
    public array $requests = [];

    /** @var callable(RequestInterface): ResponseInterface */
    private $handler;

    /**
     * @param callable(RequestInterface): ResponseInterface $handler
     */
    public function __construct(callable $handler)
    {
        $this->handler = $handler;
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;

        return ($this->handler)($request);
    }

    /**
     * A client whose transport always fails at the network level.
     */
    public static function failingNetwork(): self
    {
        return new self(static function (): never {
            throw new class('connection refused') extends \RuntimeException implements NetworkExceptionInterface {
                public function getRequest(): RequestInterface
                {
                    throw new \LogicException('not implemented');
                }
            };
        });
    }

    /**
     * A client whose transport fails with a generic (e.g. timeout) error.
     */
    public static function failingTimeout(): self
    {
        return new self(static function (): never {
            throw new class('timed out') extends \RuntimeException implements ClientExceptionInterface {
            };
        });
    }
}
