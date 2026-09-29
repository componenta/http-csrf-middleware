<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf\Tests;

use Componenta\Http\Middleware\Csrf\CsrfMiddleware;
use Componenta\Http\Middleware\Csrf\HmacCsrfTokenManager;
use InvalidArgumentException;
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
        $request = $this->unsafeRequest();
        $request = $channel === 'header'
            ? $request->withHeader('X-CSRF-Token', $attackerToken)
            : $request->withParsedBody(['_csrf_token' => $attackerToken]);
        $handler = new CsrfProtectedHandler();

        $response = (new CsrfMiddleware($this->manager('session-B'), new Psr17Factory()))
            ->process($request, $handler);

        self::assertSame(403, $response->getStatusCode());
        self::assertFalse($response->hasHeader('X-CSRF-Failure'));
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame(0, $handler->calls);
    }

    #[DataProvider('submissionChannels')]
    public function testOwnSessionSubmissionWorksAcrossRequests(string $channel): void
    {
        $token = $this->manager('session-A')->generate();
        $request = $this->unsafeRequest();
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

    /**
     * @return iterable<string, array{string}>
     */
    public static function submissionChannels(): iterable
    {
        yield 'header' => ['header'];
        yield 'form' => ['form'];
    }

    public function testInvalidOrEmptyHeaderCannotFallBackToValidBodyToken(): void
    {
        $valid = $this->manager('session-A')->generate();

        foreach ([
            $this->manager('session-B')->generate(),
            '',
        ] as $header) {
            $request = $this->unsafeRequest()
                ->withHeader('X-CSRF-Token', $header)
                ->withParsedBody(['_csrf_token' => $valid]);
            $handler = new CsrfProtectedHandler();

            $response = (new CsrfMiddleware($this->manager('session-A'), new Psr17Factory()))
                ->process($request, $handler);

            self::assertSame(403, $response->getStatusCode());
            self::assertSame(0, $handler->calls);
        }
    }

    public function testMultipleTokenHeaderValuesAreRejected(): void
    {
        $token = $this->manager('session-A')->generate();
        $handler = new CsrfProtectedHandler();

        $response = (new CsrfMiddleware($this->manager('session-A'), new Psr17Factory()))
            ->process(
                $this->unsafeRequest()->withHeader('X-CSRF-Token', [$token, $token]),
                $handler,
            );

        self::assertSame(403, $response->getStatusCode());
        self::assertSame(0, $handler->calls);
    }

    public function testSafeRequestReceivesTokenAndUnsafeMissingTokenIsRejected(): void
    {
        $middleware = new CsrfMiddleware($this->manager('session-A'), new Psr17Factory());
        $handler = new CsrfProtectedHandler();

        self::assertSame(204, $middleware->process(
            new ServerRequest('GET', 'https://shop.example/form'),
            $handler,
        )->getStatusCode());
        self::assertTrue($this->manager('session-A')->validate($handler->token ?? ''));

        self::assertSame(403, $middleware->process($this->unsafeRequest(), $handler)->getStatusCode());
        self::assertSame(1, $handler->calls);
    }

    public function testMissingOriginAndRefererAreBlockedByDefault(): void
    {
        $token = $this->manager('session-A')->generate();
        $handler = new CsrfProtectedHandler();

        $response = (new CsrfMiddleware($this->manager('session-A'), new Psr17Factory()))
            ->process(
                (new ServerRequest('POST', 'https://shop.example/change'))
                    ->withHeader('X-CSRF-Token', $token),
                $handler,
            );

        self::assertSame(403, $response->getStatusCode());
        self::assertSame(0, $handler->calls);
    }

    public function testMissingOriginCanBeExplicitlyAllowedForLegacyClients(): void
    {
        $token = $this->manager('session-A')->generate();
        $handler = new CsrfProtectedHandler();
        $middleware = new CsrfMiddleware(
            $this->manager('session-A'),
            new Psr17Factory(),
            allowMissingOrigin: true,
        );

        $response = $middleware->process(
            (new ServerRequest('POST', 'https://shop.example/change'))
                ->withHeader('X-CSRF-Token', $token),
            $handler,
        );

        self::assertSame(204, $response->getStatusCode());
        self::assertSame(1, $handler->calls);
    }

    public function testRefererIsUsedAsStrictFallback(): void
    {
        $token = $this->manager('session-A')->generate();
        $handler = new CsrfProtectedHandler();

        $response = (new CsrfMiddleware($this->manager('session-A'), new Psr17Factory()))
            ->process(
                (new ServerRequest('POST', 'https://shop.example/change'))
                    ->withHeader('Referer', 'https://shop.example/forms/edit?id=1')
                    ->withHeader('X-CSRF-Token', $token),
                $handler,
            );

        self::assertSame(204, $response->getStatusCode());
        self::assertSame(1, $handler->calls);
    }

    #[DataProvider('rejectedOrigins')]
    public function testOpaqueAndHostileOriginsAreRejectedEvenWithValidToken(string $origin): void
    {
        $token = $this->manager('session-A')->generate();
        $handler = new CsrfProtectedHandler();

        $response = (new CsrfMiddleware($this->manager('session-A'), new Psr17Factory()))
            ->process(
                (new ServerRequest('POST', 'https://shop.example/change'))
                    ->withHeader('Origin', $origin)
                    ->withHeader('X-CSRF-Token', $token),
                $handler,
            );

        self::assertSame(403, $response->getStatusCode());
        self::assertSame(0, $handler->calls);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function rejectedOrigins(): iterable
    {
        yield 'opaque null' => ['null'];
        yield 'different origin' => ['https://other.example'];
    }

    public function testInvalidTargetOriginFailsClosed(): void
    {
        $handler = new CsrfProtectedHandler();

        $response = (new CsrfMiddleware($this->manager('session-A'), new Psr17Factory()))
            ->process(
                (new ServerRequest('POST', '/change'))
                    ->withHeader('Origin', 'https://shop.example')
                    ->withHeader('X-CSRF-Token', $this->manager('session-A')->generate()),
                $handler,
            );

        self::assertSame(403, $response->getStatusCode());
        self::assertSame(0, $handler->calls);
    }

    public function testCrossSiteFetchMetadataIsRejectedBeforeTokenValidation(): void
    {
        $handler = new CsrfProtectedHandler();

        $response = (new CsrfMiddleware(
            $this->manager('session-A'),
            new Psr17Factory(),
            checkOrigin: false,
        ))->process(
            (new ServerRequest('POST', 'https://shop.example/change'))
                ->withHeader('Sec-Fetch-Site', 'cross-site')
                ->withHeader('Origin', 'https://evil.example')
                ->withHeader('X-CSRF-Token', $this->manager('session-A')->generate()),
            $handler,
        );

        self::assertSame(403, $response->getStatusCode());
        self::assertSame(0, $handler->calls);
    }

    public function testExplicitTrustedOriginCanPassCrossSiteFetchMetadata(): void
    {
        $token = $this->manager('session-A')->generate();
        $handler = new CsrfProtectedHandler();
        $middleware = new CsrfMiddleware(
            $this->manager('session-A'),
            new Psr17Factory(),
            trustedOrigins: ['https://app.example'],
        );

        $response = $middleware->process(
            (new ServerRequest('POST', 'https://shop.example/change'))
                ->withHeader('Sec-Fetch-Site', 'cross-site')
                ->withHeader('Origin', 'https://app.example')
                ->withHeader('X-CSRF-Token', $token),
            $handler,
        );

        self::assertSame(204, $response->getStatusCode());
    }

    public function testUnknownFetchMetadataFallsBackToOriginAndTokenValidation(): void
    {
        $handler = new CsrfProtectedHandler();
        $token = $this->manager('session-A')->generate();

        $response = (new CsrfMiddleware(
            $this->manager('session-A'),
            new Psr17Factory(),
        ))->process(
            (new ServerRequest('POST', 'https://shop.example/change'))
                ->withHeader('Sec-Fetch-Site', 'future-value')
                ->withHeader('Origin', 'https://shop.example')
                ->withHeader('X-CSRF-Token', $token),
            $handler,
        );

        self::assertSame(204, $response->getStatusCode());
        self::assertSame(1, $handler->calls);
    }

    public function testUnknownFetchMetadataDoesNotBypassOriginValidation(): void
    {
        $handler = new CsrfProtectedHandler();

        $response = (new CsrfMiddleware(
            $this->manager('session-A'),
            new Psr17Factory(),
        ))->process(
            (new ServerRequest('POST', 'https://shop.example/change'))
                ->withHeader('Sec-Fetch-Site', 'future-value')
                ->withHeader('Origin', 'https://evil.example')
                ->withHeader('X-CSRF-Token', $this->manager('session-A')->generate()),
            $handler,
        );

        self::assertSame(403, $response->getStatusCode());
        self::assertSame(0, $handler->calls);
    }

    public function testSuccessfulUnsafeResponseVariesOnSecurityContextHeaders(): void
    {
        $middleware = new CsrfMiddleware($this->manager('session-A'), new Psr17Factory());
        $handler = new CsrfProtectedHandler(new Response(204, ['Vary' => 'Accept-Encoding']));
        $request = $this->unsafeRequest()
            ->withHeader('Sec-Fetch-Site', 'same-origin')
            ->withHeader('X-CSRF-Token', $this->manager('session-A')->generate());

        $response = $middleware->process($request, $handler);

        self::assertSame(
            'Accept-Encoding, Origin, Sec-Fetch-Site',
            $response->getHeaderLine('Vary'),
        );
    }

    public function testSuccessfulUnsafeResponsePreservesVaryWildcard(): void
    {
        $middleware = new CsrfMiddleware($this->manager('session-A'), new Psr17Factory());
        $handler = new CsrfProtectedHandler(new Response(204, ['Vary' => '*']));
        $request = $this->unsafeRequest()
            ->withHeader('Sec-Fetch-Site', 'same-origin')
            ->withHeader('X-CSRF-Token', $this->manager('session-A')->generate());

        $response = $middleware->process($request, $handler);

        self::assertSame('*', $response->getHeaderLine('Vary'));
    }

    public function testExcludedPathUsesPathSegmentBoundaryAndDoesNotInjectToken(): void
    {
        $middleware = new CsrfMiddleware(
            $this->manager('session-A'),
            new Psr17Factory(),
            excludedPaths: ['/webhook'],
        );

        $webhook = new CsrfProtectedHandler();
        self::assertSame(204, $middleware->process(
            new ServerRequest('POST', 'https://shop.example/webhook/provider'),
            $webhook,
        )->getStatusCode());
        self::assertNull($webhook->token);

        $lookalike = new CsrfProtectedHandler();
        self::assertSame(403, $middleware->process(
            $this->unsafeRequest('/webhook-admin'),
            $lookalike,
        )->getStatusCode());
        self::assertSame(0, $lookalike->calls);
    }

    #[DataProvider('unsafeConfigurations')]
    public function testUnsafeConfigurationIsRejected(string $case, string $value): void
    {
        $this->expectException(InvalidArgumentException::class);

        match ($case) {
            'trustedOrigin' => new CsrfMiddleware(
                $this->manager('session-A'),
                new Psr17Factory(),
                trustedOrigins: [$value],
            ),
            'excludedPath' => new CsrfMiddleware(
                $this->manager('session-A'),
                new Psr17Factory(),
                excludedPaths: [$value],
            ),
            'headerName' => new CsrfMiddleware(
                $this->manager('session-A'),
                new Psr17Factory(),
                headerName: $value,
            ),
            default => self::fail('Unknown unsafe configuration case.'),
        };
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function unsafeConfigurations(): iterable
    {
        yield 'trusted origin contains path' => ['trustedOrigin', 'https://example.test/path'];
        yield 'empty excluded path' => ['excludedPath', ''];
        yield 'root excluded path' => ['excludedPath', '/'];
        yield 'header injection' => ['headerName', "X-CSRF\r\nInjected"];
    }

    public function testFailureReasonHeaderIsOptInOnly(): void
    {
        $request = $this->unsafeRequest()
            ->withHeader('Origin', 'https://evil.example')
            ->withHeader('X-CSRF-Token', $this->manager('session-A')->generate());

        $default = (new CsrfMiddleware($this->manager('session-A'), new Psr17Factory()))
            ->process($request, new CsrfProtectedHandler());
        self::assertFalse($default->hasHeader('X-CSRF-Failure'));

        $debug = (new CsrfMiddleware(
            $this->manager('session-A'),
            new Psr17Factory(),
            debugFailureHeader: true,
        ))->process($request, new CsrfProtectedHandler());

        self::assertSame('origin_mismatch', $debug->getHeaderLine('X-CSRF-Failure'));
    }

    private function manager(string $binding): HmacCsrfTokenManager
    {
        return new HmacCsrfTokenManager(
            str_repeat('k', 32),
            3600,
            $binding,
            clock: static fn(): int => 2_000_000_000,
        );
    }

    private function unsafeRequest(string $path = '/change'): ServerRequest
    {
        return (new ServerRequest('POST', 'https://shop.example' . $path))
            ->withHeader('Origin', 'https://shop.example');
    }
}

final class CsrfProtectedHandler implements RequestHandlerInterface
{
    public int $calls = 0;
    public ?string $token = null;

    public function __construct(
        private readonly ResponseInterface $response = new Response(204),
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        ++$this->calls;
        $token = $request->getAttribute(CsrfMiddleware::ATTR_TOKEN);
        $this->token = is_string($token) ? $token : null;

        return $this->response;
    }
}
