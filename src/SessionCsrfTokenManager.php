<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf;

/**
 * Synchronizer token stored in an active native PHP session.
 *
 * Reuse getActive() for forms; generate() replaces the stored token.
 * Session persistence must be available before a token can be issued.
 */
final class SessionCsrfTokenManager implements CsrfTokenManagerInterface
{
    private const int TOKEN_BYTES = 32;

    /**
     * @param string $sessionKey Key used to store the token in $_SESSION
     */
    public function __construct(
        private readonly string $sessionKey = '_csrf_token',
    ) {}

    public function generate(): string
    {
        $this->ensureSessionStarted();

        $token = bin2hex(random_bytes(self::TOKEN_BYTES));
        $_SESSION[$this->sessionKey] = $token;

        return $token;
    }

    public function validate(string $token): bool
    {
        $this->ensureSessionStarted();

        $stored = $_SESSION[$this->sessionKey] ?? null;

        if (!is_string($stored) || $stored === '' || $token === '') {
            return false;
        }

        return hash_equals($stored, $token);
    }

    public function getActive(): ?string
    {
        $this->ensureSessionStarted();

        $token = $_SESSION[$this->sessionKey] ?? null;

        return is_string($token) && $token !== '' ? $token : null;
    }

    /**
     * Ensures a PHP session is active.
     *
     * Sessions are required for the Synchronizer Token Pattern since
     * the token must be stored server-side and associated with the
     * user's session.
     */
    private function ensureSessionStarted(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        if (session_status() === PHP_SESSION_DISABLED || !session_start()) {
            throw new \RuntimeException('Could not start the PHP session required for CSRF protection.');
        }
    }
}
