<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf;

use Componenta\Http\HttpMethod;
use Componenta\Http\Origin;
use InvalidArgumentException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class CsrfMiddleware implements MiddlewareInterface
{
    public const string ATTR_TOKEN = 'csrf_token';
    /** @deprecated Pass the token manager explicitly to consumers instead. */
    public const string ATTR_TOKEN_MANAGER = 'csrf_token_manager';

    /** @var list<Origin> */
    private readonly array $trustedOrigins;

    /** @var list<string> */
    private readonly array $excludedPaths;

    private readonly ?Origin $targetOrigin;

    /**
     * @param CsrfTokenManagerInterface|(\Closure(ServerRequestInterface): mixed) $tokenManager
     * @param list<string> $trustedOrigins
     * @param list<string> $excludedPaths
     */
    public function __construct(
        private readonly CsrfTokenManagerInterface|\Closure $tokenManager,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly string $headerName = 'X-CSRF-Token',
        private readonly string $fieldName = '_csrf_token',
        private readonly bool $checkOrigin = true,
        array $trustedOrigins = [],
        array $excludedPaths = [],
        private readonly bool $checkFetchMetadata = true,
        private readonly bool $allowMissingOrigin = false,
        private readonly bool $debugFailureHeader = false,
        ?string $targetOrigin = null,
        private readonly bool $exposeTokenManager = true,
    ) {
        if (preg_match("@^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+$@D", $headerName) !== 1) {
            throw new InvalidArgumentException('CSRF token header name must be a valid HTTP field name.');
        }

        if (
            $fieldName === ''
            || strlen($fieldName) > 256
            || preg_match('/[\x00-\x1f\x7f]/', $fieldName) === 1
        ) {
            throw new InvalidArgumentException('CSRF form field name is invalid.');
        }

        $this->trustedOrigins = self::normalizeTrustedOrigins($trustedOrigins);
        $this->excludedPaths = self::normalizeExcludedPaths($excludedPaths);
        $this->targetOrigin = self::normalizeTargetOrigin($targetOrigin);
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if ($this->isExcludedPath($request)) {
            return $handler->handle($request);
        }

        if ($this->isSafeMethod($request)) {
            return $handler->handle($this->injectToken($request, $this->managerFor($request)));
        }

        try {
            if ($this->checkFetchMetadata) {
                $this->verifyFetchMetadata($request);
            }

            if ($this->checkOrigin) {
                $this->verifyOrigin($request);
            }

            $manager = $this->managerFor($request);
            $this->verifyToken($request, $manager);
        } catch (InvalidCsrfTokenException $exception) {
            return $this->forbidden($exception->reason);
        }

        return $this->addSecurityVary(
            $handler->handle($this->injectToken($request, $manager)),
        );
    }

    private function isSafeMethod(ServerRequestInterface $request): bool
    {
        return HttpMethod::isSafe($request->getMethod());
    }

    private function isExcludedPath(ServerRequestInterface $request): bool
    {
        $path = $request->getUri()->getPath();

        if (!self::isUnambiguousExclusionPath($path)) {
            return false;
        }

        foreach ($this->excludedPaths as $prefix) {
            if ($path === $prefix || str_starts_with($path, $prefix . '/')) {
                return true;
            }
        }

        return false;
    }

    private static function isUnambiguousExclusionPath(string $path): bool
    {
        if (str_contains($path, '\\') || preg_match('/[\x00-\x1f\x7f]/', $path) === 1) {
            return false;
        }

        // Exemptions are deliberately limited to plain, unambiguous paths.
        // Do not attempt to predict a proxy/router's percent-decoding policy.
        if (str_contains($path, '%') || str_contains($path, ';') || str_contains($path, '//')) {
            return false;
        }

        foreach (explode('/', $path) as $segment) {
            if ($segment === '.' || $segment === '..') {
                return false;
            }
        }

        return true;
    }

    /**
     * Fetch Metadata is a browser-controlled defense-in-depth signal.
     * Explicit trusted origins remain usable for intentional cross-site clients.
     */
    private function verifyFetchMetadata(ServerRequestInterface $request): void
    {
        $site = strtolower($request->getHeaderLine('Sec-Fetch-Site'));

        if ($site === '') {
            return;
        }

        if (!in_array($site, ['same-origin', 'same-site', 'cross-site', 'none'], true)) {
            return;
        }

        if ($site !== 'cross-site') {
            return;
        }

        $source = Origin::fromSerialized($request->getHeaderLine('Origin'));

        if ($source !== null && !$source->opaque && $this->isTrustedOrigin($source)) {
            return;
        }

        throw new InvalidCsrfTokenException(
            'fetch_metadata_cross_site',
            'Cross-site unsafe request rejected by Fetch Metadata policy',
        );
    }

    private function verifyOrigin(ServerRequestInterface $request): void
    {
        $hasOrigin = $request->hasHeader('Origin');
        $hasReferer = $request->hasHeader('Referer');

        if (!$hasOrigin && !$hasReferer) {
            if ($this->allowMissingOrigin) {
                return;
            }

            throw new InvalidCsrfTokenException(
                'origin_missing',
                'Origin and Referer headers are both absent',
            );
        }

        $uri = $request->getUri();
        $target = $this->targetOrigin ?? Origin::fromComponents($uri->getScheme(), $uri->getHost(), $uri->getPort());

        if ($target === null || $target->opaque) {
            throw new InvalidCsrfTokenException(
                'target_origin_invalid',
                'Target origin cannot be determined safely',
            );
        }

        if ($hasOrigin) {
            $origins = $request->getHeader('Origin');
            $source = count($origins) === 1 ? Origin::fromSerialized(array_values($origins)[0]) : null;

            if ($source === null) {
                throw new InvalidCsrfTokenException('origin_malformed', 'Origin header is malformed');
            }

            if ($source->opaque) {
                throw new InvalidCsrfTokenException('origin_null', 'Opaque Origin is not trusted');
            }

            if ($source->equals($target) || $this->isTrustedOrigin($source)) {
                return;
            }

            throw new InvalidCsrfTokenException(
                'origin_mismatch',
                'Origin header does not match target origin',
            );
        }

        $referers = $request->getHeader('Referer');
        $source = count($referers) === 1 ? Origin::fromUri(array_values($referers)[0]) : null;

        if ($source === null || $source->opaque) {
            throw new InvalidCsrfTokenException(
                'referer_malformed',
                'Referer header is malformed',
            );
        }

        if (!$source->equals($target) && !$this->isTrustedOrigin($source)) {
            throw new InvalidCsrfTokenException(
                'referer_mismatch',
                'Referer origin does not match target origin',
            );
        }
    }

    private function verifyToken(ServerRequestInterface $request, CsrfTokenManagerInterface $manager): void
    {
        $token = $this->extractToken($request);

        if ($token === null) {
            throw new InvalidCsrfTokenException(
                'token_missing',
                'CSRF token not found in request',
            );
        }

        if ($token === '' || !$manager->validate($token)) {
            throw new InvalidCsrfTokenException(
                'token_invalid',
                'CSRF token is invalid or expired',
            );
        }
    }

    private function extractToken(ServerRequestInterface $request): ?string
    {
        if ($request->hasHeader($this->headerName)) {
            $values = array_values($request->getHeader($this->headerName));

            return count($values) === 1 ? $values[0] : '';
        }

        $body = $request->getParsedBody();

        if (!is_array($body) || !array_key_exists($this->fieldName, $body)) {
            return null;
        }

        return is_string($body[$this->fieldName]) ? $body[$this->fieldName] : '';
    }

    private function isTrustedOrigin(Origin $origin): bool
    {
        foreach ($this->trustedOrigins as $trusted) {
            if ($trusted->equals($origin)) {
                return true;
            }
        }

        return false;
    }

    private function managerFor(ServerRequestInterface $request): CsrfTokenManagerInterface
    {
        $manager = $this->tokenManager instanceof \Closure
            ? ($this->tokenManager)($request)
            : $this->tokenManager;
        if (!$manager instanceof CsrfTokenManagerInterface) {
            throw new \UnexpectedValueException('CSRF manager resolver must return a token manager.');
        }
        return $manager;
    }

    private function injectToken(ServerRequestInterface $request, CsrfTokenManagerInterface $manager): ServerRequestInterface
    {
        $token = $manager->getActive() ?? $manager->generate();
        $request = $request->withAttribute(self::ATTR_TOKEN, $token);

        return $this->exposeTokenManager
            ? $request->withAttribute(self::ATTR_TOKEN_MANAGER, $manager)
            : $request->withoutAttribute(self::ATTR_TOKEN_MANAGER);
    }

    private function addSecurityVary(ResponseInterface $response): ResponseInterface
    {
        $headers = [];

        if ($this->checkOrigin) {
            $headers[] = 'Origin';
            $headers[] = 'Referer';
        }

        if ($this->checkFetchMetadata) {
            $headers[] = 'Sec-Fetch-Site';
        }

        if ($headers === []) {
            return $response;
        }

        $current = [];

        foreach ($response->getHeader('Vary') as $line) {
            foreach (explode(',', $line) as $part) {
                $value = trim($part);

                if ($value === '') {
                    continue;
                }

                if ($value === '*') {
                    return $response->withHeader('Vary', '*');
                }

                $key = strtolower($value);

                if (!array_key_exists($key, $current)) {
                    $current[$key] = $value;
                }
            }
        }

        foreach ($headers as $header) {
            $key = strtolower($header);

            if (!array_key_exists($key, $current)) {
                $current[$key] = $header;
            }
        }

        return $response->withHeader('Vary', array_values($current));
    }

    private function forbidden(string $reason): ResponseInterface
    {
        $response = $this->responseFactory->createResponse(403)
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');

        return $this->debugFailureHeader
            ? $response->withHeader('X-CSRF-Failure', $reason)
            : $response;
    }

    private static function normalizeTargetOrigin(?string $value): ?Origin
    {
        if ($value === null) {
            return null;
        }

        $origin = Origin::fromSerialized($value);

        if ($origin === null || $origin->opaque) {
            throw new InvalidArgumentException(sprintf(
                'CSRF target origin "%s" must be an explicit HTTP(S) origin.',
                $value,
            ));
        }

        return $origin;
    }

    /**
     * @param array<array-key, mixed> $origins
     * @return list<Origin>
     */
    private static function normalizeTrustedOrigins(array $origins): array
    {
        $normalized = [];
        $seen = [];

        foreach ($origins as $value) {
            if (!is_string($value)) {
                throw new InvalidArgumentException('Trusted CSRF origins must be strings.');
            }

            $origin = Origin::fromSerialized($value);

            if ($origin === null || $origin->opaque) {
                throw new InvalidArgumentException(sprintf(
                    'Trusted CSRF origin "%s" must be an explicit HTTP(S) origin.',
                    $value,
                ));
            }

            $key = (string) $origin;

            if (!isset($seen[$key])) {
                $normalized[] = $origin;
                $seen[$key] = true;
            }
        }

        return $normalized;
    }

    /**
     * @param array<array-key, mixed> $paths
     * @return list<string>
     */
    private static function normalizeExcludedPaths(array $paths): array
    {
        $normalized = [];

        foreach ($paths as $path) {
            if (
                !is_string($path)
                || $path === ''
                || $path === '/'
                || $path[0] !== '/'
                || str_contains($path, '?')
                || str_contains($path, '#')
                || !self::isUnambiguousExclusionPath($path)
            ) {
                throw new InvalidArgumentException(
                    'Excluded CSRF paths must be unambiguous non-root absolute path prefixes without query or fragment.',
                );
            }

            $path = rtrim($path, '/');

            if ($path === '') {
                throw new InvalidArgumentException('Excluded CSRF paths must not normalize to the root.');
            }

            if (!in_array($path, $normalized, true)) {
                $normalized[] = $path;
            }
        }

        return $normalized;
    }
}
