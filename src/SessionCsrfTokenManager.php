<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf;

use InvalidArgumentException;
use RuntimeException;

final class SessionCsrfTokenManager implements CsrfTokenManagerInterface
{
    private const int TOKEN_BYTES = 32;

    public function __construct(
        private readonly string $sessionKey = '_csrf_token',
    ) {
        if (
            $sessionKey === ''
            || strlen($sessionKey) > 256
            || preg_match('/[\x00-\x1f\x7f]/', $sessionKey) === 1
        ) {
            throw new InvalidArgumentException('CSRF session key is invalid.');
        }
    }

    public function generate(): string
    {
        $this->ensureSessionStarted();

        $token = bin2hex(random_bytes(self::TOKEN_BYTES));
        $_SESSION[$this->sessionKey] = $token;

        return $token;
    }

    public function validate(#[\SensitiveParameter] string $token): bool
    {
        $this->ensureSessionStarted();

        $stored = $_SESSION[$this->sessionKey] ?? null;

        if (
            !is_string($stored)
            || !self::isValidToken($stored)
            || !self::isValidToken($token)
        ) {
            return false;
        }

        return hash_equals($stored, $token);
    }

    public function getActive(): ?string
    {
        $this->ensureSessionStarted();

        $token = $_SESSION[$this->sessionKey] ?? null;

        return is_string($token) && self::isValidToken($token) ? $token : null;
    }

    private static function isValidToken(string $token): bool
    {
        return preg_match('/\A[0-9a-f]{64}\z/D', $token) === 1;
    }

    private function ensureSessionStarted(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        if (session_status() === PHP_SESSION_DISABLED || !session_start()) {
            throw new RuntimeException('Could not start the PHP session required for CSRF protection.');
        }
    }
}
