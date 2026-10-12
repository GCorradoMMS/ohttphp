<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Tests;

use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;
use Stringable;

/**
 * Minimal in-memory PSR-3 logger used to assert that no sensitive data is
 * written to application logs.
 */
final class InMemoryLogger extends AbstractLogger implements LoggerInterface
{
    /** @var list<array{level: string, message: string, context: array<string, mixed>}> */
    public array $records = [];

    /**
     * @param mixed $level
     * @param Stringable|string $message
     * @param array<string, mixed> $context
     */
    public function log($level, Stringable|string $message, array $context = []): void
    {
        $this->records[] = [
            'level' => is_scalar($level) ? (string) $level : 'unknown',
            'message' => (string) $message,
            'context' => $context,
        ];
    }
}
