<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf\Tests;

use Componenta\Http\Middleware\Csrf\ComponentaSessionCsrfTokenManager;
use Componenta\Http\Middleware\Csrf\CsrfMiddleware;
use Componenta\Session\Session;
use Componenta\Session\SessionId;
use Componenta\Session\SessionInterface;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class ComponentaSessionCsrfTokenManagerTest extends TestCase
{
    public function testTokenIsStoredAndInvalidatedAfterSessionIdRotation(): void
    {
        $session = new Session(new SessionId('first-session'));
        $manager = new ComponentaSessionCsrfTokenManager($session);
        self::assertNull($manager->getActive());
        $token = $manager->generate();
        self::assertSame($token, (new ComponentaSessionCsrfTokenManager($session))->getActive());
        self::assertTrue($manager->validate($token));
        $session->id = new SessionId('rotated-session');
        self::assertNull($manager->getActive());
        self::assertFalse($manager->validate($token));
        $replacement = $manager->generate();
        self::assertNotSame($token, $replacement);
        self::assertTrue($manager->validate($replacement));
    }

    public function testMalformedStoredDataIsNotAccepted(): void
    {
        $session = new Session(new SessionId('session'));
        $manager = new ComponentaSessionCsrfTokenManager($session);
        $session->data->set('_csrf_token_v2', ['binding' => [], 'token' => str_repeat('a', 64)]);
        self::assertNull($manager->getActive());
        self::assertFalse($manager->validate(str_repeat('a', 64)));
    }

    public function testMissingSessionFailsExplicitly(): void
    {
        $this->expectException(\RuntimeException::class);
        ComponentaSessionCsrfTokenManager::fromRequest((new Psr17Factory())->createServerRequest('GET', '/'));
    }

    public function testSharedMiddlewareDoesNotAcceptAnotherSessionsToken(): void
    {
        $factory = new Psr17Factory();
        $first = new Session(new SessionId('first-session'));
        $second = new Session(new SessionId('second-session'));
        $token = (new ComponentaSessionCsrfTokenManager($first))->generate();
        (new ComponentaSessionCsrfTokenManager($second))->generate();
        $middleware = new CsrfMiddleware(
            ComponentaSessionCsrfTokenManager::fromRequest(...),
            $factory,
            targetOrigin: 'https://example.test',
            exposeTokenManager: false,
        );
        $handler = new class implements RequestHandlerInterface {
            public int $calls = 0;
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                ++$this->calls;
                return (new Psr17Factory())->createResponse(204);
            }
        };
        $request = $factory->createServerRequest('POST', 'https://example.test/')
            ->withHeader('Origin', 'https://example.test')
            ->withHeader('X-CSRF-Token', $token);
        self::assertSame(403, $middleware->process($request->withAttribute(SessionInterface::class, $second), $handler)->getStatusCode());
        self::assertSame(204, $middleware->process($request->withAttribute(SessionInterface::class, $first), $handler)->getStatusCode());
        self::assertSame(1, $handler->calls);
    }
}
