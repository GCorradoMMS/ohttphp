<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Http;

use Psr\Http\Message\MessageInterface;

use function array_map;
use function array_merge;
use function array_unique;
use function array_values;
use function explode;
use function in_array;
use function strtolower;
use function trim;

/**
 * Removal of hop-by-hop header fields (RFC 9110, Section 7.6.1), including
 * headers nominated by the Connection header field, before a message is
 * forwarded or encoded.
 */
final class HopByHopHeaders
{
    private const STANDARD = [
        'connection',
        'keep-alive',
        'proxy-authenticate',
        'proxy-authorization',
        'proxy-connection',
        'te',
        'trailer',
        'transfer-encoding',
        'upgrade',
    ];

    private function __construct()
    {
    }

    /**
     * The lowercase names of hop-by-hop headers in the message, including
     * any headers nominated by its Connection field.
     *
     * @return list<string>
     */
    public static function names(MessageInterface $message): array
    {
        $names = self::STANDARD;
        $connection = $message->getHeaderLine('connection');
        if ($connection !== '') {
            foreach (explode(',', $connection) as $nominated) {
                $name = strtolower(trim($nominated));
                if ($name !== '' && !in_array($name, $names, true)) {
                    $names[] = $name;
                }
            }
        }

        return $names;
    }

    /**
     * A copy of the message without hop-by-hop header fields. The Host
     * header is also removed when $stripHost is set: HTTP clients derive
     * it from the request URI, and a stale value could bypass authority
     * validation.
     *
     * @template T of MessageInterface
     * @param T $message
     * @return T
     */
    public static function strip(MessageInterface $message, bool $stripHost = false): MessageInterface
    {
        $names = self::names($message);
        if ($stripHost) {
            $names = array_values(array_unique(array_merge($names, ['host'])));
        }
        foreach ($names as $name) {
            $message = $message->withoutHeader($name);
        }

        return $message;
    }
}
