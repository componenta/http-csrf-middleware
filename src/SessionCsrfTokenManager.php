<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf;

/**
 * Session-based CSRF token manager using the Synchronizer Token Pattern.
 *
 * This is the OWASP-recommended defense against CSRF attacks. A random
 * token is generated per session and stored server-side. The token is
 * embedded in forms and submitted with each state-changing request.
 *
 * Token generation uses random_bytes() which sources entropy from the
 * operating system's CSPRNG (e.g., /dev/urandom on Linux, CryptGenRandom
 * on Windows), satisfying RFC 4086 §5 requirements for unpredictability.
 *
 * Per-session tokens are used rather than per-request tokens. Per-request
 * tokens break browser back/forward navigation, tabbed browsing, and
 * concurrent form submissions without providing meaningful additional
 * security for most applications.
 *
 * @see RFC 4086 §5      - Randomness Requirements for Security
 * @see OWASP CSRF Prevention Cheat Sheet - Synchronizer Token Pattern
 */
final class SessionCsrfTokenManager implements CsrfTokenManagerInterface
{
    /**
     * Token length in bytes before hex encoding.
     *
     * 32 bytes = 256 bits of entropy, well above the 128-bit minimum
     * recommended by OWASP. The hex-encoded token will be 64 characters.
     */
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

        // Constant-time comparison to prevent timing attacks.
        // hash_equals() is guaranteed to take the same amount of time
        // regardless of where strings differ.
        return hash_equals($stored, $token);
    }

    public function getActive(): ?string
    {
        $this->ensureSessionStarted();

        return $_SESSION[$this->sessionKey] ?? null;
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
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }
}
