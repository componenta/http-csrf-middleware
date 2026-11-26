<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf\Tests;

use Componenta\Http\Middleware\Csrf\SessionCsrfTokenManager;
use Componenta\Http\Middleware\Csrf\CsrfMiddleware;
use Componenta\Session\Session;
use Componenta\Session\SessionId;
use Componenta\Session\SessionInterface;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class SessionCsrfTokenManagerTest extends TestCase
{
    public function testTokenIsStoredAndInvalidatedAfterSessionIdRotation(): void
    {
        $session = new Session(new SessionId('first-session'));
        $manager = new SessionCsrfTokenManager($session);
        self::assertNull($manager->getActive());
        $token = $manager->generate();
        self::assertSame($token, (new SessionCsrfTokenManager($session))->getActive());
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
        $manager = new SessionCsrfTokenManager($session);
        $session->data->set('_csrf_token_v2', ['binding' => [], 'token' => str_repeat('a', 64)]);
        self::assertNull($manager->getActive());
        self::assertFalse($manager->validate(str_repeat('a', 64)));
    }

    /** @return iterable<array{string}> */
    public static function invalidSessionKeys(): iterable
    {
        yield [''];
        yield [str_repeat('x', 257)];
        yield ["bad\r\nkey"];
        yield ["bad\0key"];
    }

    #[DataProvider('invalidSessionKeys')]
    public function testInvalidSessionKeyIsRejected(string $key): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new SessionCsrfTokenManager(new Session(new SessionId('session')), $key);
    }

    public function testMaximumLengthSessionKeyAndIndependentNamespaces(): void
    {
        $session = new Session(new SessionId('session'));
        $key = str_repeat('k', 256);
        $first = new SessionCsrfTokenManager($session, $key);
        $second = new SessionCsrfTokenManager($session, 'other');
        $token = $first->generate();

        self::assertNull($second->getActive());
        self::assertFalse($second->validate($token));
        $other = $second->generate();
        self::assertTrue((new SessionCsrfTokenManager($session, $key))->validate($token));
        self::assertTrue($second->validate($other));
        self::assertFalse($first->validate($other));
    }

    public function testCopiedStorageCannotAuthorizeDifferentSession(): void
    {
        $first = new Session(new SessionId('session-one'));
        $second = new Session(new SessionId('session-two'));
        $manager = new SessionCsrfTokenManager($first);
        $token = $manager->generate();
        $second->data->set('_csrf_token_v2', $first->data->get('_csrf_token_v2', null));

        $other = new SessionCsrfTokenManager($second);
        self::assertNull($other->getActive());
        self::assertFalse($other->validate($token));
    }

    public function testMalformedStorageIsRejectedEvenWithARealSessionBinding(): void
    {
        $session = new Session(new SessionId('session'));
        $manager = new SessionCsrfTokenManager($session);
        $token = $manager->generate();
        $record = $session->data->get('_csrf_token_v2', null);
        self::assertIsArray($record);
        foreach ([
            'not-a-record',
            new \stdClass(),
            [],
            ['token' => $token],
            ['binding' => $record['binding']],
            [...$record, 'binding' => 1],
            [...$record, 'token' => 1],
            [...$record, 'token' => 'short'],
            [...$record, 'token' => str_repeat('A', 64)],
            [...$record, 'token' => $token . "\n"],
        ] as $invalid) {
            $session->data->set('_csrf_token_v2', $invalid);
            self::assertNull($manager->getActive());
            self::assertFalse($manager->validate($token));
        }
        $session->data->set('_csrf_token_v2', $record);
        self::assertTrue($manager->validate($token));
    }

    public function testMissingSessionFailsExplicitly(): void
    {
        $this->expectException(\RuntimeException::class);
        SessionCsrfTokenManager::fromRequest((new Psr17Factory())->createServerRequest('GET', '/'));
    }

    public function testSharedMiddlewareDoesNotAcceptAnotherSessionsToken(): void
    {
        $factory = new Psr17Factory();
        $first = new Session(new SessionId('first-session'));
        $second = new Session(new SessionId('second-session'));
        $token = (new SessionCsrfTokenManager($first))->generate();
        (new SessionCsrfTokenManager($second))->generate();
        $middleware = new CsrfMiddleware(
            SessionCsrfTokenManager::fromRequest(...),
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
