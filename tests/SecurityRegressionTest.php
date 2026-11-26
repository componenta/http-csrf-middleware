<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf\Tests;

use Componenta\Http\Middleware\Csrf\CsrfMiddleware;
use Componenta\Http\Middleware\Csrf\CsrfTokenManagerInterface;
use Componenta\Http\Middleware\Csrf\Origin;
use InvalidArgumentException;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SecurityRegressionTest extends TestCase
{
    public static function rootAliases(): iterable
    {
        yield ['//'];
        yield ['///'];
        yield ["/hook\0"];
        yield ["/hook\n"];
    }

    #[DataProvider('rootAliases')]
    public function testUnsafeExclusionsAreRejected(string $path): void
    {
        $this->expectException(InvalidArgumentException::class);
        new CsrfMiddleware(
            $this->createStub(CsrfTokenManagerInterface::class),
            new Psr17Factory(),
            excludedPaths: [$path],
        );
    }

    public function testRefererWithAtSignInResourceIsValid(): void
    {
        $origin = Origin::fromUri('https://example.test/users/@alice?email=a@b.test');
        self::assertNotNull($origin);
        self::assertSame('https://example.test', (string) $origin);
        self::assertNull(Origin::fromUri('https://alice@example.test/path'));
    }
}
