<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf\Tests;

use Componenta\Http\Middleware\Csrf\CsrfMiddleware;
use Componenta\Http\Middleware\Csrf\HmacCsrfTokenManager;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class CsrfMiddlewareTest extends TestCase
{
    #[DataProvider('submissionChannels')]
    public function testCrossSessionSubmissionIsForbidden(string $channel): void
    {
        $attackerToken = $this->manager('session-A')->generate();
        $request = new ServerRequest('POST', 'https://shop.example/change');
        $request = $channel === 'header'
            ? $request->withHeader('X-CSRF-Token', $attackerToken)
            : $request->withParsedBody(['_csrf_token' => $attackerToken]);
        $handler = new CsrfProtectedHandler();
        $middleware = new CsrfMiddleware($this->manager('session-B'), new Psr17Factory());

        $response = $middleware->process($request, $handler);

        self::assertSame(403, $response->getStatusCode());
        self::assertSame('token_invalid', $response->getHeaderLine('X-CSRF-Failure'));
        self::assertSame(0, $handler->calls);
    }

    #[DataProvider('submissionChannels')]
    public function testOwnSessionSubmissionWorksAcrossRequests(string $channel): void
    {
        $token = $this->manager('session-A')->generate();
        $request = new ServerRequest('POST', 'https://shop.example/change');
        $request = $channel === 'header'
            ? $request->withHeader('X-CSRF-Token', $token)
            : $request->withParsedBody(['_csrf_token' => $token]);
        $handler = new CsrfProtectedHandler();

        $response = (new CsrfMiddleware($this->manager('session-A'), new Psr17Factory()))
            ->process($request, $handler);

        self::assertSame(204, $response->getStatusCode());
        self::assertSame(1, $handler->calls);
        self::assertTrue($this->manager('session-A')->validate($handler->token ?? ''));
    }

    public static function submissionChannels(): iterable
    {
        yield 'header' => ['header'];
        yield 'form' => ['form'];
    }

    public function testInvalidHeaderCannotFallBackToValidBodyToken(): void
    {
        $request = (new ServerRequest('POST', 'https://shop.example/change'))
            ->withHeader('X-CSRF-Token', $this->manager('session-B')->generate())
            ->withParsedBody(['_csrf_token' => $this->manager('session-A')->generate()]);
        $handler = new CsrfProtectedHandler();

        $response = (new CsrfMiddleware($this->manager('session-A'), new Psr17Factory()))
            ->process($request, $handler);

        self::assertSame(403, $response->getStatusCode());
        self::assertSame(0, $handler->calls);
    }

    public function testSafeRequestReceivesTokenAndUnsafeMissingTokenIsRejected(): void
    {
        $middleware = new CsrfMiddleware($this->manager('session-A'), new Psr17Factory());
        $handler = new CsrfProtectedHandler();

        self::assertSame(204, $middleware->process(
            new ServerRequest('GET', 'https://shop.example/form'), $handler,
        )->getStatusCode());
        self::assertTrue($this->manager('session-A')->validate($handler->token ?? ''));
        self::assertSame(403, $middleware->process(
            new ServerRequest('POST', 'https://shop.example/change'), $handler,
        )->getStatusCode());
        self::assertSame(1, $handler->calls);
    }

    public function testHostileOriginIsRejectedEvenWithValidToken(): void
    {
        $request = (new ServerRequest('POST', 'https://shop.example/change'))
            ->withHeader('Origin', 'https://other.example')
            ->withHeader('X-CSRF-Token', $this->manager('session-A')->generate());
        $handler = new CsrfProtectedHandler();

        $response = (new CsrfMiddleware($this->manager('session-A'), new Psr17Factory()))
            ->process($request, $handler);

        self::assertSame(403, $response->getStatusCode());
        self::assertSame('origin_mismatch', $response->getHeaderLine('X-CSRF-Failure'));
        self::assertSame(0, $handler->calls);
    }

    private function manager(string $binding): HmacCsrfTokenManager
    {
        return new HmacCsrfTokenManager(
            str_repeat('k', 32), 3600, $binding, clock: static fn(): int => 2000000000,
        );
    }
}

final class CsrfProtectedHandler implements RequestHandlerInterface
{
    public int $calls = 0;
    public ?string $token = null;

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $this->calls++;
        $token = $request->getAttribute(CsrfMiddleware::ATTR_TOKEN);
        $this->token = is_string($token) ? $token : null;

        return new Response(204);
    }
}
