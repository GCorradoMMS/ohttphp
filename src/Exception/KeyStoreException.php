<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Exception;

/**
 * Thrown when a gateway key store cannot fulfill an operation, or when
 * stored key material is missing, corrupted, or inconsistent.
 *
 * Exception messages MUST NOT contain key material.
 */
final class KeyStoreException extends OhttphpException
{
}
