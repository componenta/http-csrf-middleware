<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf\Tests;

use Componenta\Http\Middleware\Csrf\HmacCsrfTokenManager;
use Componenta\Http\Middleware\Csrf\Tests\Support\LegacyHmacFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class HmacCsrfTokenManagerTest extends TestCase
{
    private const string KEY = 'test-only-key-with-at-least-32-bytes';

    public function testSameBindingWorksAcrossRequestsWithoutExposingIt(): void
    {
        $issuer = $this->manager('session-A:1');
        $verifier = $this->manager('session-A:1');
        $token = $issuer->generate();

        self::assertTrue($issuer->validate($token));
        self::assertTrue($verifier->validate($token));
        self::assertSame($token, $issuer->getActive());
        self::assertStringNotContainsString('session-A:1', $token);
        self::assertStringNotContainsString(self::KEY, print_r($issuer, true));
        self::assertStringNotContainsString('session-A:1', print_r($issuer, true));
    }

    #[DataProvider('otherBindings')]
    public function testTokenCannotMoveToAnotherSessionOrGeneration(string $binding): void
    {
        $token = $this->manager('session-A:1')->generate();

        self::assertFalse($this->manager($binding)->validate($token));
    }

    public static function otherBindings(): iterable
    {
        yield 'another session' => ['session-B:1'];
        yield 'rotated generation' => ['session-A:2'];
        yield 'binary suffix' => ["session-A:1\0"];
    }

    public function testLegacyUnboundSignatureIsRejected(): void
    {
        $payload = str_repeat('a', 32) . '.2000000000';
        $legacy = $payload . '.' . hash_hmac('sha256', $payload, self::KEY);

        self::assertFalse($this->manager()->validate($legacy));
        self::assertFalse($this->manager()->validate('v2.' . $legacy));
    }

    public function testTamperedAndMalformedTokensAreRejected(): void
    {
        $manager = $this->manager();
        $token = $manager->generate();
        $parts = explode('.', $token);
        $badNonce = $parts;
        $badNonce[1][0] = $badNonce[1][0] === 'a' ? 'b' : 'a';
        $badTime = $parts;
        $badTime[2] = '2000000001';
        $badMac = $parts;
        $badMac[3][0] = $badMac[3][0] === 'a' ? 'b' : 'a';

        foreach ([
            '', implode('.', $badNonce), implode('.', $badTime), implode('.', $badMac),
            "v3." . substr($token, 3), $token . "\n", $token . '.extra',
            str_repeat('x', 4096), str_replace('.2000000000.', '.02000000000.', $token),
        ] as $invalid) {
            self::assertFalse($manager->validate($invalid));
        }
    }

    public function testExpiryAndActiveTokenUseTheClock(): void
    {
        $now = 2000000000;
        $manager = new HmacCsrfTokenManager(
            self::KEY, 60, 'session-A:1', clock: static function () use (&$now): int { return $now; },
        );
        $token = $manager->generate();
        $now += 60;
        self::assertTrue($manager->validate($token));
        $now++;
        self::assertFalse($manager->validate($token));
        self::assertNull($manager->getActive());
    }

    public function testFutureSkewIsBounded(): void
    {
        $token = $this->manager(now: 2000000030)->generate();
        self::assertTrue($this->manager()->validate($token));

        $tooEarly = $this->manager(now: 2000000031)->generate();
        self::assertFalse($this->manager()->validate($tooEarly));
    }

    public function testDifferentKeyCannotVerifyToken(): void
    {
        $token = $this->manager()->generate();
        $other = new HmacCsrfTokenManager(str_repeat('z', 32), 3600, 'session-A:1');

        self::assertFalse($other->validate($token));
    }

    #[DataProvider('invalidConfiguration')]
    public function testInvalidConfigurationIsRejected(string $key, string $binding, int $ttl): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new HmacCsrfTokenManager($key, $ttl, $binding);
    }

    public static function invalidConfiguration(): iterable
    {
        yield 'short key' => ['short', 'session-A:1', 60];
        yield 'empty binding' => [self::KEY, '', 60];
        yield 'oversized binding' => [self::KEY, str_repeat('s', 4097), 60];
        yield 'zero ttl' => [self::KEY, 'session-A:1', 0];
        yield 'negative ttl' => [self::KEY, 'session-A:1', -1];
    }

    public function testInvalidClockFailsExplicitly(): void
    {
        $manager = new HmacCsrfTokenManager(self::KEY, 3600, 'session-A:1', clock: static fn() => 'invalid');

        $this->expectException(\UnexpectedValueException::class);
        $manager->generate();
    }


    public function testLegacyTtlArgumentCannotBecomeASharedBindingInWeakMode(): void
    {
        $this->expectException(\ArgumentCountError::class);

        LegacyHmacFactory::withoutClock(self::KEY);
    }

    #[DataProvider('legacyClocks')]
    public function testLegacyClockArgumentCannotBecomeABindingInWeakMode(?\Closure $clock): void
    {
        $this->expectException(\TypeError::class);

        LegacyHmacFactory::withClock(self::KEY, $clock);
    }

    public static function legacyClocks(): iterable
    {
        yield 'default clock' => [null];
        yield 'custom clock' => [static fn(): int => 2000000000];
    }

    private function manager(string $binding = 'session-A:1', int $now = 2000000000): HmacCsrfTokenManager
    {
        return new HmacCsrfTokenManager(self::KEY, 3600, $binding, clock: static fn(): int => $now);
    }
}
