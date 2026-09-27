<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf;

/**
 * HMAC tokens bound to one trusted session context, without token storage.
 *
 * Create a new manager for each request/session. The binding must come from
 * server-side session state and change on login or credential rotation.
 */
final class HmacCsrfTokenManager implements CsrfTokenManagerInterface
{
    private const int NONCE_BYTES = 16;
    private const int MAX_TOKEN_LENGTH = 120;
    private const string DOMAIN = "componenta-csrf-hmac-v2\0";

    private ?string $activeToken = null;

    /** @var (\Closure(): mixed)|null */
    private readonly ?\Closure $clock;

    /**
     * @param string $sessionBinding Trusted session identity, optionally with its generation.
     * @param (\Closure(): mixed)|null $clock Must return a positive integer Unix timestamp.
     */
    public function __construct(
        #[\SensitiveParameter]
        private readonly string $secretKey,
        private readonly int $ttl,
        #[\SensitiveParameter]
        private readonly string $sessionBinding,
        ?\Closure $clock = null,
    ) {
        if (strlen($secretKey) < 32 || strlen($secretKey) > 4096) {
            throw new \InvalidArgumentException('HMAC key must contain between 32 and 4096 bytes.');
        }

        if ($sessionBinding === '' || strlen($sessionBinding) > 4096) {
            throw new \InvalidArgumentException('CSRF session binding must contain between 1 and 4096 bytes.');
        }

        if ($ttl < 1) {
            throw new \InvalidArgumentException('CSRF token lifetime must be positive.');
        }

        $this->clock = $clock;
    }

    #[\Override]
    public function generate(): string
    {
        $nonce = bin2hex(random_bytes(self::NONCE_BYTES));
        $timestamp = (string) $this->now();
        $signature = $this->sign($nonce, $timestamp);

        return $this->activeToken = "v2.{$nonce}.{$timestamp}.{$signature}";
    }

    #[\Override]
    public function validate(#[\SensitiveParameter] string $token): bool
    {
        if (
            strlen($token) > self::MAX_TOKEN_LENGTH
            || preg_match('/\Av2\.([0-9a-f]{32})\.([1-9][0-9]{0,18})\.([0-9a-f]{64})\z/D', $token, $parts) !== 1
        ) {
            return false;
        }

        [, $nonce, $timestamp, $signature] = $parts;
        $tokenTime = filter_var($timestamp, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);

        if (
            $tokenTime === false
            || !hash_equals($this->sign($nonce, $timestamp), $signature)
        ) {
            return false;
        }

        $now = $this->now();

        return $now - $tokenTime <= $this->ttl && $tokenTime - $now <= 30;
    }

    #[\Override]
    public function getActive(): ?string
    {
        return $this->activeToken !== null && $this->validate($this->activeToken)
            ? $this->activeToken
            : null;
    }

    /** @return array{ttl: int, secretKey: string, sessionBinding: string, activeToken: string} */
    public function __debugInfo(): array
    {
        return [
            'ttl' => $this->ttl,
            'secretKey' => '[REDACTED]',
            'sessionBinding' => '[REDACTED]',
            'activeToken' => '[REDACTED]',
        ];
    }

    private function sign(string $nonce, string $timestamp): string
    {
        // Length-prefix the opaque binding; never include it in the public token.
        return hash_hmac(
            'sha256',
            self::DOMAIN . pack('N', strlen($this->sessionBinding))
                . $this->sessionBinding . $nonce . '.' . $timestamp,
            $this->secretKey,
        );
    }

    private function now(): int
    {
        $now = $this->clock !== null ? ($this->clock)() : time();

        if (!is_int($now) || $now < 1) {
            throw new \UnexpectedValueException('CSRF clock must return a positive Unix timestamp.');
        }

        return $now;
    }
}
