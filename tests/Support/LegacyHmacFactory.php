<?php

// Intentionally use weak typing to exercise legacy consumer call shapes.
namespace Componenta\Http\Middleware\Csrf\Tests\Support;

use Componenta\Http\Middleware\Csrf\HmacCsrfTokenManager;
use ReflectionClass;

final class LegacyHmacFactory
{
    public static function withoutClock(string $key): HmacCsrfTokenManager
    {
        /** @var HmacCsrfTokenManager */
        return (new ReflectionClass(HmacCsrfTokenManager::class))
            ->newInstanceArgs([$key, 60]);
    }

    public static function withClock(string $key, ?\Closure $clock): HmacCsrfTokenManager
    {
        /** @var HmacCsrfTokenManager */
        return (new ReflectionClass(HmacCsrfTokenManager::class))
            ->newInstanceArgs([$key, 60, $clock]);
    }
}
