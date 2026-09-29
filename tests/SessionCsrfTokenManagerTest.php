<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf\Tests;

use Componenta\Http\Middleware\Csrf\SessionCsrfTokenManager;
use PHPUnit\Framework\Attributes\BackupGlobals;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[BackupGlobals(true)]
final class SessionCsrfTokenManagerTest extends TestCase
{
    protected function setUp(): void
    {
        // No files, cookies, or shared developer session storage.
        session_set_save_handler(new InMemoryCsrfSessionHandler(), false);
        session_id('csrf-package-test');
    }

    protected function tearDown(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
    }

    public function testGeneratedTokenIsAvailableAcrossManagerInstances(): void
    {
        $token = (new SessionCsrfTokenManager())->generate();
        $manager = new SessionCsrfTokenManager();

        self::assertSame($token, $manager->getActive());
        self::assertTrue($manager->validate($token));
        $replacement = $manager->generate();
        self::assertTrue($manager->validate($replacement));
        self::assertFalse($manager->validate($token));
    }

    public function testMalformedSessionValueDoesNotCauseATypeError(): void
    {
        $manager = new SessionCsrfTokenManager();
        $manager->generate();
        $_SESSION['_csrf_token'] = ['attacker-value'];

        self::assertNull($manager->getActive());
        self::assertFalse($manager->validate('attacker-value'));
        self::assertTrue($manager->validate($manager->generate()));
    }

    public function testMalformedStringSessionValueIsUnavailable(): void
    {
        $manager = new SessionCsrfTokenManager();
        $manager->generate();
        $_SESSION['_csrf_token'] = 'weak-token';

        self::assertNull($manager->getActive());
        self::assertFalse($manager->validate('weak-token'));
    }

    #[DataProvider('invalidSessionKeys')]
    public function testInvalidSessionKeyIsRejected(string $key): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new SessionCsrfTokenManager($key);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidSessionKeys(): iterable
    {
        yield 'empty' => [''];
        yield 'control characters' => ["bad\r\nkey"];
        yield 'too long' => [str_repeat('k', 257)];
    }

    public function testMaximumSessionKeyLengthIsAccepted(): void
    {
        $manager = new SessionCsrfTokenManager(str_repeat('k', 256));

        $token = $manager->generate();

        self::assertTrue($manager->validate($token));
    }

    public function testEmptySessionValueIsUnavailable(): void
    {
        $manager = new SessionCsrfTokenManager();
        $manager->generate();
        $_SESSION['_csrf_token'] = '';

        self::assertNull($manager->getActive());
        self::assertFalse($manager->validate(''));
    }

    public function testFailedSessionStartupDoesNotIssueAnUnstoredToken(): void
    {
        session_set_save_handler(new InMemoryCsrfSessionHandler(false), false);
        // Capture PHP's expected storage warning; the manager must still throw.
        set_error_handler(static fn(int $severity, string $message): bool => $severity === E_WARNING);
        try {
            $this->expectException(\RuntimeException::class);
            (new SessionCsrfTokenManager())->generate();
        } finally {
            restore_error_handler();
        }
    }
}

final class InMemoryCsrfSessionHandler implements \SessionHandlerInterface
{
    public function __construct(private bool $available = true) {}
    public function open(string $path, string $name): bool { return $this->available; }
    public function close(): bool { return true; }
    public function read(string $id): string { return ''; }
    public function write(string $id, string $data): bool { return true; }
    public function destroy(string $id): bool { return true; }
    public function gc(int $max_lifetime): int { return 0; }
}
