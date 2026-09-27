<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf\Tests;

use Componenta\Http\Middleware\Csrf\CookieCsrfTokenManager;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\BackupGlobals;
use PHPUnit\Framework\TestCase;

#[BackupGlobals(true)]
final class CookieCsrfTokenManagerTest extends TestCase
{
    public function testGeneratedTokenReplacesTheIncomingCookieForThisRequest(): void
    {
        $_COOKIE['csrf_token'] = str_repeat('a', 64);
        $manager = new CookieCsrfTokenManager();

        $token = $manager->generate();

        self::assertSame($token, $manager->getActive());
        self::assertTrue($manager->validate($token));
        self::assertFalse($manager->validate(str_repeat('a', 64)));
        $manager->clear();
        self::assertNull($manager->getActive());
        self::assertFalse($manager->validate($token));
    }

    #[DataProvider('malformedCookies')]
    public function testMalformedCookiesAreUnavailable(mixed $value): void
    {
        $_COOKIE['csrf_token'] = $value;
        $manager = new CookieCsrfTokenManager();

        self::assertNull($manager->getActive());
        self::assertFalse($manager->validate('attacker-value'));
    }

    public static function malformedCookies(): iterable
    {
        yield 'array' => [['attacker-value']];
        yield 'integer' => [123];
        yield 'empty' => [''];
        yield 'wrong format' => ['attacker-value'];
    }

    public function testExistingGeneratedCookieCanBeValidated(): void
    {
        $_COOKIE['csrf_token'] = str_repeat('a', 64);
        $manager = new CookieCsrfTokenManager();

        self::assertTrue($manager->validate(str_repeat('a', 64)));
        self::assertFalse($manager->validate(str_repeat('b', 64)));
    }

    public function testInvalidSameSiteFailsAtConfiguration(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new CookieCsrfTokenManager(sameSite: 'typo');
    }

    public function testSupportedSameSiteIsCaseInsensitive(): void
    {
        $manager = new CookieCsrfTokenManager(sameSite: 'lax');

        self::assertTrue($manager->validate($manager->generate()));
    }
}
