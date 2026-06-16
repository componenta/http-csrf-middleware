<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf;

/**
 * Contract for CSRF token generation and validation.
 *
 * Implementations MUST use cryptographically secure random number
 * generators for token generation per RFC 4086 §5 (Randomness
 * Requirements for Security).
 *
 * Implementations MUST use constant-time comparison for token
 * validation to prevent timing side-channel attacks.
 *
 * @see RFC 4086 - Randomness Requirements for Security
 */
interface CsrfTokenManagerInterface
{
    /**
     * Generates a new CSRF token.
     *
     * The returned token MUST contain sufficient entropy to resist
     * brute-force attacks. A minimum of 128 bits of entropy is
     * RECOMMENDED per OWASP guidelines.
     */
    public function generate(): string;

    /**
     * Validates a submitted CSRF token.
     *
     * Implementations MUST use constant-time comparison (hash_equals)
     * to prevent timing attacks per RFC 4086 §5.
     */
    public function validate(string $token): bool;

    /**
     * Retrieves the current active token without generating a new one.
     *
     * Returns null if no token has been generated yet.
     */
    public function getActive(): ?string;
}
