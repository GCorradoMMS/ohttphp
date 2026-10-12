<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Tests;

use Nyholm\Psr7\Uri;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;

/**
 * Minimal PSR-7 request implementation without any header validation, used
 * to exercise encoder-side validation of field lines that compliant PSR-7
 * implementations refuse to construct.
 *
 * @phpstan-type Headers array<string, list<string>>
 */
final class UnvalidatedRequest implements RequestInterface
{
    /** @var Headers */
    private array $headers = [];

    private readonly StreamInterface $body;

    public function __construct(
        private readonly string $method = 'GET',
        private readonly UriInterface $uri = new Uri('https://example.com/'),
        ?StreamInterface $body = null,
    ) {
        $stream = $body ?? null;
        if ($stream === null) {
            $resource = fopen('php://memory', 'rb');
            if (!is_resource($resource)) {
                throw new \RuntimeException('Unable to open memory stream');
            }
            $stream = new \Nyholm\Psr7\Stream($resource);
        }
        $this->body = $stream;
    }

    public function withAddedHeader(string $name, $value): static
    {
        $clone = clone $this;
        foreach ((array) $value as $single) {
            $clone->headers[strtolower($name)][] = $single;
        }

        return $clone;
    }

    public function getRequestTarget(): string
    {
        return $this->uri->getPath() ?: '/';
    }

    public function withRequestTarget(string $requestTarget): static
    {
        throw new \LogicException('Not implemented');
    }

    public function getMethod(): string
    {
        return $this->method;
    }

    public function withMethod(string $method): static
    {
        throw new \LogicException('Not implemented');
    }

    public function getUri(): UriInterface
    {
        return $this->uri;
    }

    public function withUri(UriInterface $uri, mixed $preserveHost = false): static
    {
        throw new \LogicException('Not implemented');
    }

    public function getProtocolVersion(): string
    {
        return '1.1';
    }

    public function withProtocolVersion(string $version): static
    {
        throw new \LogicException('Not implemented');
    }

    public function getHeaders(): array
    {
        return $this->headers;
    }

    public function hasHeader(string $name): bool
    {
        return isset($this->headers[strtolower($name)]);
    }

    public function getHeader(string $name): array
    {
        return $this->headers[strtolower($name)] ?? [];
    }

    public function getHeaderLine(string $name): string
    {
        return implode(',', $this->getHeader($name));
    }

    public function withHeader(string $name, $value): static
    {
        $clone = clone $this;
        unset($clone->headers[strtolower($name)]);
        foreach ((array) $value as $single) {
            $clone->headers[strtolower($name)][] = $single;
        }

        return $clone;
    }

    public function withoutHeader(string $name): static
    {
        $clone = clone $this;
        unset($clone->headers[strtolower($name)]);

        return $clone;
    }

    public function getBody(): StreamInterface
    {
        return $this->body;
    }

    public function withBody(StreamInterface $body): static
    {
        throw new \LogicException('Not implemented');
    }
}
