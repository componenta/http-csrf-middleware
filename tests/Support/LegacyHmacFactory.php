<?php

// Intentionally use weak typing to exercise consumers without strict_types.
namespace Componenta\Http\Middleware\Csrf\Tests\Support;

use Componenta\Http\Middleware\Csrf\HmacCsrfTokenManager;

final class LegacyHmacFactory
{
    public static function withoutClock(string $key): HmacCsrfTokenManager
    {
        return new HmacCsrfTokenManager($key, 60);
    }

    public static function withClock(string $key, ?\Closure $clock): HmacCsrfTokenManager
    {
        return new HmacCsrfTokenManager($key, 60, $clock);
    }
}
