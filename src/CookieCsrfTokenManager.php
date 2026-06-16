<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf;

/**
 * Cookie-based CSRF token manager.
 *
 * Stores the CSRF token in an httpOnly cookie and validates submitted
 * tokens against the stored value using constant-time comparison.
 *
 * Note: this implementation uses setcookie() directly, which is not
 * PSR-7 compatible. For middleware-first architectures, prefer
 * HmacCsrfTokenManager (stateless) or SessionCsrfTokenManager.
 */
final class CookieCsrfTokenManager implements CsrfTokenManagerInterface
{
    private ?string $token = null;
    private bool $tokenRead = false;

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
        private readonly string $sameSite = 'Strict',
    ) {}

    #[\Override]
    public function generate(): string
    {
        $this->token = bin2hex(random_bytes(32));
        $this->setCookie($this->token);

        return $this->token;
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
            $this->token = $_COOKIE[$this->cookieName] ?? null;
            $this->tokenRead = true;
        }

        return $this->token;
    }

    /**
     * Clears the token by expiring the cookie.
     */
    public function clear(): void
    {
        $this->token = null;
        $this->tokenRead = true;

        $this->setCookie('', time() - 3600);
    }

    private function setCookie(string $value, ?int $expires = null): void
    {
        $expires ??= time() + $this->ttl;

        setcookie($this->cookieName, $value, [
            'expires' => $expires,
            'path' => $this->path,
            'domain' => $this->domain,
            'secure' => $this->secure,
            'httponly' => true,
            'samesite' => $this->sameSite,
        ]);
    }
}
