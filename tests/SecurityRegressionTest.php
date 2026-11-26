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
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class SecurityRegressionTest extends TestCase
{
    /** @return iterable<array{string}> */
    public static function rootAliases(): iterable
    {
        yield ['//'];
        yield ['///'];
        yield ['/hook/%252e'];
        yield ['/hook/..;param'];
        yield ['/hook//sub'];
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

    public function testSingleMiddlewareUsesDifferentRequestManagers(): void
    {
        $factory = new Psr17Factory();
        $calls = 0;
        $first = $this->createStub(CsrfTokenManagerInterface::class);
        $first->method('getActive')->willReturn('first-session-token');
        $second = $this->createStub(CsrfTokenManagerInterface::class);
        $second->method('getActive')->willReturn('second-session-token');
        $middleware = new CsrfMiddleware(
            static function (ServerRequestInterface $request) use (&$calls, $first, $second): CsrfTokenManagerInterface {
                ++$calls;
                return $request->getAttribute('session') === 'a' ? $first : $second;
            },
            $factory,
            exposeTokenManager: false,
        );
        $handler = new class implements RequestHandlerInterface {
            /** @var list<array{mixed, mixed}> */
            public array $tokens = [];
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->tokens[] = [$request->getAttribute(CsrfMiddleware::ATTR_TOKEN), $request->getAttribute(CsrfMiddleware::ATTR_TOKEN_MANAGER)];
                return (new Psr17Factory())->createResponse(204);
            }
        };
        foreach (['a', 'b'] as $session) {
            $request = $factory->createServerRequest('GET', 'https://example.test/')->withAttribute('session', $session);
            self::assertSame(204, $middleware->process($request, $handler)->getStatusCode());
        }
        self::assertSame(2, $calls);
        self::assertSame([['first-session-token', null], ['second-session-token', null]], $handler->tokens);
    }

    public function testEquivalentIpv6OriginsHaveEqualIdentity(): void
    {
        $first = Origin::fromSerialized('https://[2001:0db8:0:0:0:0:0:1]');
        $second = Origin::fromSerialized('https://[2001:db8::1]');
        self::assertNotNull($first);
        self::assertNotNull($second);
        self::assertTrue($first->equals($second));
        self::assertNull(Origin::fromSerialized('https://example.test:'));
    }

    public function testRefererWithAtSignInResourceIsValid(): void
    {
        $origin = Origin::fromUri('https://example.test/users/@alice?email=a@b.test');
        self::assertNotNull($origin);
        self::assertSame('https://example.test', (string) $origin);
        self::assertNull(Origin::fromUri('https://alice@example.test/path'));
    }
}
