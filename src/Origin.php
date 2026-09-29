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

        if ($value === '' || trim($value) !== $value || str_contains($value, '@')) {
            return null;
        }

        $parsed = parse_url($value);

        if (
            $parsed === false
            || !isset($parsed['scheme'], $parsed['host'])
            || isset($parsed['user'])
            || isset($parsed['pass'])
            || isset($parsed['path'])
            || isset($parsed['query'])
            || isset($parsed['fragment'])
        ) {
            return null;
        }

        return self::fromComponents(
            $parsed['scheme'],
            $parsed['host'],
            $parsed['port'] ?? null,
        );
    }

    public static function fromUri(string $value): ?self
    {
        if ($value === '' || trim($value) !== $value || str_contains($value, '@')) {
            return null;
        }

        $parsed = parse_url($value);

        if (
            $parsed === false
            || !isset($parsed['scheme'], $parsed['host'])
            || isset($parsed['user'])
            || isset($parsed['pass'])
        ) {
            return null;
        }

        return self::fromComponents(
            $parsed['scheme'],
            $parsed['host'],
            $parsed['port'] ?? null,
        );
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

        if ($port === 0) {
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
