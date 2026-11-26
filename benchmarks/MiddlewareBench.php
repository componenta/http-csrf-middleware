<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf\Benchmarks;

use Componenta\Http\Middleware\Csrf\CsrfMiddleware;
use Componenta\Http\Middleware\Csrf\HmacCsrfTokenManager;
use Nyholm\Psr7\Factory\Psr17Factory;
use PhpBench\Attributes as Bench;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

#[Bench\BeforeMethods('setUp')]
#[Bench\Iterations(5)]
#[Bench\Revs(1000)]
final class CsrfBench
{
    private HmacCsrfTokenManager $manager;
    private CsrfMiddleware $middleware;
    private RequestHandlerInterface $handler;
    private ServerRequestInterface $safe;
    private ServerRequestInterface $valid;
    private ServerRequestInterface $invalid;
    private string $token;

    public function setUp(): void
    {
        $factory = new Psr17Factory();
        $this->manager = new HmacCsrfTokenManager(str_repeat('k', 32), 600, 'benchmark-session', static fn(): int => 1000);
        $this->token = $this->manager->generate();
        $this->middleware = new CsrfMiddleware($this->manager, $factory, targetOrigin: 'https://app.example.test', exposeTokenManager: false);
        $this->safe = $factory->createServerRequest('GET', 'https://app.example.test/');
        $this->valid = $factory->createServerRequest('POST', 'https://app.example.test/')
            ->withHeader('Origin', 'https://app.example.test')
            ->withHeader('X-CSRF-Token', $this->token);
        $this->invalid = $this->valid->withHeader('X-CSRF-Token', 'invalid');
        $this->handler = new class($factory->createResponse(204)) implements RequestHandlerInterface {
            public function __construct(private readonly ResponseInterface $response) {}
            public function handle(ServerRequestInterface $request): ResponseInterface { return $this->response; }
        };
    }

    public function benchHmacGenerate(): void { $this->manager->generate(); }
    public function benchHmacValidate(): void { if (!$this->manager->validate($this->token)) { throw new \RuntimeException('Unexpected invalid token.'); } }
    public function benchSafeRequest(): void { $this->run($this->safe, 204); }
    public function benchValidUnsafeRequest(): void { $this->run($this->valid, 204); }
    public function benchInvalidUnsafeRequest(): void { $this->run($this->invalid, 403); }

    private function run(ServerRequestInterface $request, int $status): void
    {
        if ($this->middleware->process($request, $this->handler)->getStatusCode() !== $status) {
            throw new \RuntimeException('Unexpected benchmark response.');
        }
    }
}
