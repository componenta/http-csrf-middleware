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
        $binding = $this->currentBinding();
        $token = bin2hex(random_bytes(self::TOKEN_BYTES));
        $_SESSION[$this->sessionKey] = ['binding' => $binding, 'token' => $token];

        return $token;
    }

    public function validate(#[\SensitiveParameter] string $token): bool
    {
        $stored = $this->getActive();

        return $stored !== null && self::isValidToken($token) && hash_equals($stored, $token);
    }

    public function getActive(): ?string
    {
        $binding = $this->currentBinding();
        $value = $_SESSION[$this->sessionKey] ?? null;
        if (!is_array($value) || !isset($value['binding'], $value['token'])
            || !is_string($value['binding']) || !is_string($value['token'])
            || !self::isValidToken($value['token'])
            || !hash_equals($binding, $value['binding'])) {
            return null;
        }

        return $value['token'];
    }

    private function currentBinding(): string
    {
        $this->ensureSessionStarted();
        $id = session_id();
        if ($id === false || $id === '') {
            throw new RuntimeException('CSRF protection requires a valid PHP session identifier.');
        }

        return hash('sha256', "componenta-native-session-csrf-v2\0" . $id);
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
