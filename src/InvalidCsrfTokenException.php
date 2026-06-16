<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf;

/**
 * Thrown when CSRF token validation fails.
 *
 * Contains the specific reason for the failure to assist with
 * logging and debugging without exposing details to the client.
 */
class InvalidCsrfTokenException extends \RuntimeException
{
    public function __construct(
        public readonly string $reason,
        string $message = 'CSRF token validation failed',
    ) {
        parent::__construct($message);
    }
}
