<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf;

use Psr\Http\Message\ServerRequestInterface;

final readonly class Origin implements \Stringable
{
    private function __construct(
        private string $value,
        public bool $opaque,
    ) {}

    public static function fromSerialized(string $value): ?self
    {
        if ($value === 'null') {
            return new self('null', true);
        }

        if (preg_match('~\A(https?)://(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::([0-9]{1,5}))?\z~iD', $value, $parts) !== 1) {
            return null;
        }
        return self::fromComponents($parts[1], $parts[2], isset($parts[3]) ? (int) $parts[3] : null);
    }

    public static function fromUri(string $value): ?self
    {
        if (preg_match('/[\x00-\x20\x7f]/', $value) === 1
            || preg_match('~\A(https?://[^/?#]+)(?:[/?#].*)?\z~iD', $value, $parts) !== 1) {
            return null;
        }
        return self::fromSerialized($parts[1]);
    }

    public static function fromRequest(ServerRequestInterface $request): ?self
    {
        $uri = $request->getUri();

        if ($uri->getScheme() === '' || $uri->getHost() === '') {
            return null;
        }

        return self::fromComponents($uri->getScheme(), $uri->getHost(), $uri->getPort());
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }

    public function __toString(): string
    {
        return $this->value;
    }

    private static function fromComponents(string $scheme, string $host, ?int $port): ?self
    {
        $scheme = strtolower($scheme);

        if (!in_array($scheme, ['http', 'https'], true)) {
            return null;
        }

        $host = strtolower($host);

        if (!self::validHost($host)) {
            return null;
        }

        if (str_starts_with($host, '[')) {
            $binary = inet_pton(substr($host, 1, -1));
            $normalized = $binary === false ? false : inet_ntop($binary);
            if ($normalized === false) {
                return null;
            }
            $host = '[' . $normalized . ']';
        }

        if ($port !== null && ($port < 1 || $port > 65535)) {
            return null;
        }

        if (($scheme === 'http' && $port === 80) || ($scheme === 'https' && $port === 443)) {
            $port = null;
        }

        return new self(
            $scheme . '://' . $host . ($port === null ? '' : ':' . $port),
            false,
        );
    }

    private static function validHost(string $host): bool
    {
        if ($host === '' || preg_match('/[\s\x00-\x1f\x7f]/', $host) === 1) {
            return false;
        }

        if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
            return filter_var(substr($host, 1, -1), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        }

        return filter_var($host, FILTER_VALIDATE_IP) !== false
            || filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
    }
}
