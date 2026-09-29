<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf;

use InvalidArgumentException;
use RuntimeException;

/**
 * @deprecated Prefer SessionCsrfTokenManager or HmacCsrfTokenManager.
 *
 * Legacy double-submit-cookie token manager. The cookie is constrained to
 * __Host- semantics to reduce sibling-subdomain cookie injection risk.
 */
final class CookieCsrfTokenManager implements CsrfTokenManagerInterface
{
    private ?string $token = null;
    private bool $tokenRead = false;

    /** @var 'Strict'|'Lax'|'None' */
    private readonly string $sameSite;

    public function __construct(
        private readonly string $cookieName = '__Host-csrf_token',
        private readonly int $ttl = 7200,
        private readonly string $path = '/',
        string $domain = '',
        private readonly bool $secure = true,
        string $sameSite = 'Strict',
    ) {
        $this->sameSite = match (strtolower($sameSite)) {
            'strict' => 'Strict',
            'lax' => 'Lax',
            'none' => 'None',
            default => throw new InvalidArgumentException('Unsupported SameSite value.'),
        };

        if ($ttl < 1) {
            throw new InvalidArgumentException('CSRF cookie lifetime must be positive.');
        }

        if (
            !str_starts_with($cookieName, '__Host-')
            || preg_match("@^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+$@D", $cookieName) !== 1
        ) {
            throw new InvalidArgumentException('Legacy CSRF cookie must use a valid __Host- cookie name.');
        }

        if (!$secure || $path !== '/' || $domain !== '') {
            throw new InvalidArgumentException(
                'Legacy CSRF cookie requires Secure, Path=/ and no Domain attribute.',
            );
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
    public function validate(#[\SensitiveParameter] string $token): bool
    {
        $stored = $this->getActive();

        if ($stored === null || preg_match('/\A[0-9a-f]{64}\z/D', $token) !== 1) {
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
            'secure' => $this->secure,
            'httponly' => true,
            'samesite' => $this->sameSite,
        ])) {
            throw new RuntimeException('Could not publish CSRF cookie.');
        }
    }
}
