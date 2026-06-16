<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf;

/**
 * Stateless HMAC-based CSRF token manager.
 *
 * Generates tokens that can be validated without server-side storage
 * by embedding a cryptographic signature. Suitable for stateless
 * architectures (e.g., APIs behind load balancers without shared sessions).
 *
 * Token format: {nonce}.{timestamp}.{signature}
 *
 * - nonce:     32 hex chars (16 bytes) from CSPRNG per RFC 4086 §5
 * - timestamp: Unix epoch seconds, used for TTL enforcement
 * - signature: HMAC-SHA256 of "nonce.timestamp" using the secret key
 *
 * The HMAC construction follows RFC 2104 using SHA-256 as the hash
 * function (from the SHA-2 family defined in FIPS 180-4).
 *
 * @see RFC 2104     - HMAC: Keyed-Hashing for Message Authentication
 * @see RFC 4086 §5  - Randomness Requirements for Security
 * @see FIPS 180-4   - Secure Hash Standard (SHA-256)
 */
final class HmacCsrfTokenManager implements CsrfTokenManagerInterface
{
    /**
     * Nonce length in bytes before hex encoding.
     *
     * 16 bytes = 128 bits of entropy for the random component.
     * Combined with the timestamp and HMAC, this provides robust
     * protection against token prediction and replay.
     */
    private const int NONCE_BYTES = 16;

    private const string HMAC_ALGO = 'sha256';

    /**
     * Last generated token, cached for getActive().
     */
    private ?string $activeToken = null;

    /**
     * @param string  $secretKey HMAC secret key. MUST be at least 32 bytes
     *                           (256 bits) of cryptographically random data.
     *                           Keys shorter than the hash output weaken the
     *                           HMAC security per RFC 2104 §3.
     * @param int     $ttl       Token time-to-live in seconds. Tokens older
     *                           than this are rejected. Default: 3600 (1 hour).
     * @param \Closure|null $clock Optional clock function for testing.
     *                              Returns current Unix timestamp.
     */
    public function __construct(
        private readonly string $secretKey,
        private readonly int $ttl = 3600,
        private readonly ?\Closure $clock = null,
    ) {
        if (strlen($secretKey) < 32) {
            throw new \InvalidArgumentException(
                'HMAC secret key must be at least 32 bytes (256 bits) per RFC 2104 §3',
            );
        }
    }

    public function generate(): string
    {
        $nonce = bin2hex(random_bytes(self::NONCE_BYTES));
        $timestamp = (string) $this->now();
        $signature = $this->sign($nonce, $timestamp);

        $this->activeToken = "{$nonce}.{$timestamp}.{$signature}";

        return $this->activeToken;
    }

    public function validate(string $token): bool
    {
        if ($token === '') {
            return false;
        }

        $parts = explode('.', $token, 3);

        if (count($parts) !== 3) {
            return false;
        }

        [$nonce, $timestamp, $signature] = $parts;

        // Validate nonce format: must be exactly 32 hex characters
        if (!preg_match('/^[0-9a-f]{32}$/i', $nonce)) {
            return false;
        }

        // Validate timestamp is numeric
        if (!ctype_digit($timestamp)) {
            return false;
        }

        // Verify HMAC signature (constant-time comparison)
        $expectedSignature = $this->sign($nonce, $timestamp);

        if (!hash_equals($expectedSignature, $signature)) {
            return false;
        }

        // Enforce TTL - reject expired tokens
        $tokenTime = (int) $timestamp;
        $now = $this->now();

        if (($now - $tokenTime) > $this->ttl) {
            return false;
        }

        // Reject tokens with future timestamps (clock skew tolerance: 30s)
        if ($tokenTime > ($now + 30)) {
            return false;
        }

        return true;
    }

    public function getActive(): ?string
    {
        return $this->activeToken;
    }

    /**
     * Computes the HMAC-SHA256 signature for the given nonce and timestamp.
     *
     * Per RFC 2104, HMAC is computed as:
     *   HMAC(K, m) = H((K ⊕ opad) ∥ H((K ⊕ ipad) ∥ m))
     *
     * PHP's hash_hmac() implements this construction.
     */
    private function sign(string $nonce, string $timestamp): string
    {
        return hash_hmac(self::HMAC_ALGO, "{$nonce}.{$timestamp}", $this->secretKey);
    }

    private function now(): int
    {
        if ($this->clock !== null) {
            return ($this->clock)();
        }

        return time();
    }
}
