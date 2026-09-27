<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf;

/**
 * Legacy unsigned double-submit-cookie token manager.
 *
 * Stores the CSRF token in an httpOnly cookie and validates submitted
 * tokens against the stored value using constant-time comparison.
 *
 * Note: this implementation uses setcookie() directly, which is not
 * PSR-7 compatible. For middleware-first architectures, prefer
 * a session-bound HmacCsrfTokenManager or SessionCsrfTokenManager.
 * This legacy mode does not protect against an attacker who can plant cookies.
 */
final class CookieCsrfTokenManager implements CsrfTokenManagerInterface
{
    private ?string $token = null;
    private bool $tokenRead = false;

    /** @var 'Strict'|'Lax'|'None' */
    private readonly string $sameSite;

    /**
     * @param string $cookieName Cookie name for storing the token
     * @param int    $ttl        Token lifetime in seconds
     * @param string $path       Cookie path
     * @param string $domain     Cookie domain (empty = current domain)
     * @param bool   $secure     Cookie only sent over HTTPS
     * @param string $sameSite   SameSite attribute (Strict, Lax, None)
     */
    public function __construct(
        private readonly string $cookieName = 'csrf_token',
        private readonly int $ttl = 7200,
        private readonly string $path = '/',
        private readonly string $domain = '',
        private readonly bool $secure = true,
        string $sameSite = 'Strict',
    ) {
        $this->sameSite = match (strtolower($sameSite)) {
            'strict' => 'Strict',
            'lax' => 'Lax',
            'none' => 'None',
            default => throw new \InvalidArgumentException('Unsupported SameSite value.'),
        };

        if ($ttl < 1) {
            throw new \InvalidArgumentException('CSRF cookie lifetime must be positive.');
        }

        if ($this->sameSite === 'None' && !$secure) {
            throw new \InvalidArgumentException('SameSite=None requires a secure cookie.');
        }
    }

    #[\Override]
    public function generate(): string
    {
        $token = bin2hex(random_bytes(32));
        $this->setCookie($token);
        $this->token = $token;
        $this->tokenRead = true;

        return $token;
    }

    #[\Override]
    public function validate(string $token): bool
    {
        $stored = $this->getActive();

        if ($stored === null || $token === '') {
            return false;
        }

        return hash_equals($stored, $token);
    }

    #[\Override]
    public function getActive(): ?string
    {
        if (!$this->tokenRead) {
            $value = $_COOKIE[$this->cookieName] ?? null;
            $this->token = is_string($value) && preg_match('/\A[0-9a-f]{64}\z/D', $value) === 1
                ? $value
                : null;
            $this->tokenRead = true;
        }

        return $this->token;
    }

    /**
     * Clears the token by expiring the cookie.
     */
    public function clear(): void
    {
        $this->setCookie('', time() - 3600);
        $this->token = null;
        $this->tokenRead = true;
    }

    private function setCookie(string $value, ?int $expires = null): void
    {
        $expires ??= time() + $this->ttl;

        if (!setcookie($this->cookieName, $value, [
            'expires' => $expires,
            'path' => $this->path,
            'domain' => $this->domain,
            'secure' => $this->secure,
            'httponly' => true,
            'samesite' => $this->sameSite,
        ])) {
            throw new \RuntimeException('Could not publish CSRF cookie.');
        }
    }
}
