<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Cross-Site Request Forgery (CSRF) protection middleware.
 *
 * Implements a multi-layer defense strategy:
 *
 * 1. **Origin/Referer verification** (defense-in-depth)
 *    Checks the Origin header (RFC 9110 §10.1.2) or Referer header
 *    (RFC 9110 §10.1.3) against the request's Host to verify that
 *    state-changing requests originate from the same site.
 *
 * 2. **Synchronizer Token validation** (primary defense)
 *    Validates a cryptographic token submitted via request header
 *    or form body field, per the OWASP Synchronizer Token Pattern.
 *
 * Safe methods (GET, HEAD, OPTIONS, TRACE) are exempt from validation
 * per RFC 9110 §9.2.1 - they MUST NOT trigger state changes and
 * therefore cannot be exploited via CSRF.
 *
 * @see RFC 9110 §9.2.1  - Safe Methods
 * @see RFC 9110 §10.1.2 - Origin
 * @see RFC 9110 §10.1.3 - Referer
 * @see RFC 9110 §7.2    - Host and :authority
 * @see OWASP CSRF Prevention Cheat Sheet
 */
final class CsrfMiddleware implements MiddlewareInterface
{
    /**
     * Methods that are "safe" per RFC 9110 §9.2.1.
     *
     * Safe methods are defined as those that do not modify server state.
     * CSRF protection is only needed for state-changing (unsafe) methods.
     */
    private const array SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS', 'TRACE'];

    /**
     * Request attribute name for the CSRF token.
     *
     * Downstream handlers and templates can retrieve the token from
     * the request to embed it in forms or meta tags.
     */
    public const string ATTR_TOKEN = 'csrf_token';

    /**
     * Request attribute name for the token manager.
     *
     * Allows downstream code to generate fresh tokens if needed.
     */
    public const string ATTR_TOKEN_MANAGER = 'csrf_token_manager';

    /**
     * @param CsrfTokenManagerInterface $tokenManager  Token generation/validation
     * @param ResponseFactoryInterface  $responseFactory PSR-17 response factory
     * @param string $headerName     HTTP header to check for the CSRF token.
     *                               X-CSRF-Token is the de facto standard.
     * @param string $fieldName      Form body field name for the CSRF token.
     * @param bool   $checkOrigin    Whether to verify Origin/Referer headers
     *                               as a defense-in-depth layer.
     * @param list<string> $trustedOrigins  Additional trusted origins beyond
     *                                      the request Host. Each entry must
     *                                      include the scheme (e.g., "https://cdn.example.com").
     * @param list<string> $excludedPaths   Path prefixes exempt from CSRF validation.
     *                                      Useful for webhook endpoints or API routes
     *                                      that use other authentication mechanisms.
     */
    public function __construct(
        private readonly CsrfTokenManagerInterface $tokenManager,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly string $headerName = 'X-CSRF-Token',
        private readonly string $fieldName = '_csrf_token',
        private readonly bool $checkOrigin = true,
        private readonly array $trustedOrigins = [],
        private readonly array $excludedPaths = [],
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Safe methods are exempt from CSRF validation per RFC 9110 §9.2.1
        if ($this->isSafeMethod($request)) {
            return $handler->handle($this->injectToken($request));
        }

        // Check path exclusions
        if ($this->isExcludedPath($request)) {
            return $handler->handle($this->injectToken($request));
        }

        try {
            // Layer 1: Origin/Referer verification (defense-in-depth)
            if ($this->checkOrigin) {
                $this->verifyOrigin($request);
            }

            // Layer 2: Synchronizer Token validation (primary defense)
            $this->verifyToken($request);
        } catch (InvalidCsrfTokenException $e) {
            return $this->forbidden($e->reason);
        }

        return $handler->handle($this->injectToken($request));
    }

    /**
     * Determines if the request uses a safe method.
     *
     * Per RFC 9110 §9.2.1, safe methods are those whose defined semantics
     * are essentially read-only. The convention is that safe methods
     * should not cause side effects.
     */
    private function isSafeMethod(ServerRequestInterface $request): bool
    {
        return in_array(strtoupper($request->getMethod()), self::SAFE_METHODS, true);
    }

    /**
     * Checks if the request path matches any excluded prefix.
     */
    private function isExcludedPath(ServerRequestInterface $request): bool
    {
        $path = $request->getUri()->getPath();

        foreach ($this->excludedPaths as $prefix) {
            if (str_starts_with($path, $prefix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Verifies the Origin or Referer header matches the target origin.
     *
     * Per RFC 9110 §10.1.2, the Origin header indicates the origin
     * that caused the user agent to send the request. For cross-origin
     * requests, this MUST differ from the target origin, allowing
     * detection of CSRF attacks.
     *
     * Per RFC 9110 §10.1.3, the Referer header contains a URI reference
     * for the resource from which the request was obtained. It serves
     * as a fallback when Origin is absent (some browsers omit Origin
     * on same-origin POST requests).
     *
     * The Fetch Standard §3.2.5 specifies that Origin is set to "null"
     * (the string) for privacy-sensitive contexts. We reject "null"
     * Origin values as they provide no meaningful verification.
     *
     * @throws InvalidCsrfTokenException If origin verification fails
     */
    private function verifyOrigin(ServerRequestInterface $request): void
    {
        $origin = $request->getHeaderLine('Origin');
        $referer = $request->getHeaderLine('Referer');

        // If neither header is present, skip origin checking.
        // Some legitimate requests (e.g., from non-browser clients,
        // or browsers with strict referrer policies) may lack both.
        // Token validation (layer 2) remains the primary defense.
        if ($origin === '' && $referer === '') {
            return;
        }

        $targetOrigin = $this->getTargetOrigin($request);

        if ($targetOrigin === null) {
            // Cannot determine target origin - skip origin check.
            // This can happen if the Host header is missing or malformed.
            return;
        }

        // Prefer Origin header (RFC 9110 §10.1.2)
        if ($origin !== '') {
            // Reject the "null" origin string - it's sent for opaque origins
            // (data: URIs, sandboxed iframes) and provides no security value.
            if (strtolower($origin) === 'null') {
                throw new InvalidCsrfTokenException('origin_null', 'Origin header is "null"');
            }

            // Normalize the Origin header by parsing it to extract
            // scheme://host[:port] and strip standard ports per RFC 6454 §5.
            // This ensures that "https://example.com:443" matches
            // "https://example.com" (port 443 is standard for HTTPS).
            //
            // Reject origins containing "@" - per RFC 6454 §5, the origin
            // serialization is "scheme://host[:port]" with no userinfo.
            // Allowing "@" could let parse_url extract a different host
            // (e.g., "https://evil.com\@example.com" -> host=example.com).
            if (str_contains($origin, '@')) {
                throw new InvalidCsrfTokenException(
                    'origin_malformed',
                    'Origin header contains userinfo (not permitted per RFC 6454)',
                );
            }

            $normalizedOrigin = $this->extractOriginFromUri($origin);

            if ($normalizedOrigin === null) {
                throw new InvalidCsrfTokenException(
                    'origin_malformed',
                    'Origin header is malformed',
                );
            }

            if ($this->originMatches($normalizedOrigin, $targetOrigin)) {
                return;
            }

            throw new InvalidCsrfTokenException(
                'origin_mismatch',
                'Origin header does not match target origin',
            );
        }

        // Fallback: check Referer header (RFC 9110 §10.1.3)
        $refererOrigin = $this->extractOriginFromUri($referer);

        if ($refererOrigin === null) {
            // Malformed Referer - cannot verify, reject to be safe
            throw new InvalidCsrfTokenException(
                'referer_malformed',
                'Referer header is malformed',
            );
        }

        if (!$this->originMatches($refererOrigin, $targetOrigin)) {
            throw new InvalidCsrfTokenException(
                'referer_mismatch',
                'Referer origin does not match target origin',
            );
        }
    }

    /**
     * Validates the CSRF token submitted with the request.
     *
     * The token is looked up in the following order:
     * 1. Request header (X-CSRF-Token by default) - preferred for
     *    JavaScript/XHR/fetch requests
     * 2. Parsed body field (_csrf_token by default) - for HTML form
     *    submissions
     *
     * @throws InvalidCsrfTokenException If token is missing or invalid
     */
    private function verifyToken(ServerRequestInterface $request): void
    {
        $token = $this->extractToken($request);

        if ($token === null) {
            throw new InvalidCsrfTokenException(
                'token_missing',
                'CSRF token not found in request',
            );
        }

        if (!$this->tokenManager->validate($token)) {
            throw new InvalidCsrfTokenException(
                'token_invalid',
                'CSRF token is invalid or expired',
            );
        }
    }

    /**
     * Extracts the CSRF token from request header or body.
     */
    private function extractToken(ServerRequestInterface $request): ?string
    {
        // 1. Check request header (preferred for XHR/fetch)
        $headerValue = $request->getHeaderLine($this->headerName);

        if ($headerValue !== '') {
            return $headerValue;
        }

        // 2. Check parsed body field (HTML form submissions)
        $body = $request->getParsedBody();

        if (is_array($body) && isset($body[$this->fieldName]) && is_string($body[$this->fieldName])) {
            return $body[$this->fieldName];
        }

        return null;
    }

    /**
     * Determines the target origin from the request.
     *
     * Per RFC 9110 §7.2, the Host header (or :authority pseudo-header
     * in HTTP/2+) identifies the target URI's authority. Combined with
     * the request scheme, this forms the target origin.
     *
     * @return string|null Origin in the form "scheme://host[:port]", or null
     *                     if the target origin cannot be determined
     */
    private function getTargetOrigin(ServerRequestInterface $request): ?string
    {
        $uri = $request->getUri();
        $scheme = $uri->getScheme();
        $host = $uri->getHost();

        if ($scheme === '' || $host === '') {
            return null;
        }

        $origin = "{$scheme}://{$host}";

        $port = $uri->getPort();

        // Include port only if it's non-standard per RFC 9110 §4.2.3
        if ($port !== null && !$this->isStandardPort($scheme, $port)) {
            $origin .= ":{$port}";
        }

        return strtolower($origin);
    }

    /**
     * Extracts the origin (scheme + host + port) from a URI string.
     *
     * Per RFC 6454 §5, the origin of a URI is the triple
     * (scheme, host, port). For standard ports, the port is omitted.
     *
     * @see RFC 6454 - The Web Origin Concept
     */
    private function extractOriginFromUri(string $uri): ?string
    {
        $parsed = parse_url($uri);

        if ($parsed === false || !isset($parsed['scheme'], $parsed['host'])) {
            return null;
        }

        // Reject URIs with userinfo in the authority component.
        // Per RFC 6454 §5, origin serialization is "scheme://host[:port]"
        // with no userinfo. parse_url may extract a different host when
        // userinfo is present (e.g., "https://evil.com@example.com" ->
        // user=evil.com, host=example.com), enabling origin confusion attacks.
        // Note: '@' in query/path/fragment does NOT produce a 'user' key.
        if (isset($parsed['user'])) {
            return null;
        }

        $origin = strtolower($parsed['scheme']) . '://' . strtolower($parsed['host']);

        if (isset($parsed['port']) && !$this->isStandardPort($parsed['scheme'], $parsed['port'])) {
            $origin .= ':' . $parsed['port'];
        }

        return $origin;
    }

    /**
     * Checks whether an origin matches the target or a trusted origin.
     *
     * All comparisons are performed on normalized origins (lowercase,
     * standard ports stripped) to ensure RFC 6454 §5 compliance.
     */
    private function originMatches(string $origin, string $targetOrigin): bool
    {
        $normalizedOrigin = strtolower($origin);

        if ($normalizedOrigin === $targetOrigin) {
            return true;
        }

        foreach ($this->trustedOrigins as $trusted) {
            // Normalize trusted origins the same way: strip standard ports
            $normalizedTrusted = $this->extractOriginFromUri($trusted);

            if ($normalizedTrusted !== null && $normalizedOrigin === $normalizedTrusted) {
                return true;
            }

            // Fallback: simple lowercase comparison for origins that
            // can't be parsed (e.g., bare hostnames configured by user)
            if ($normalizedOrigin === strtolower($trusted)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determines if a port is the standard port for the given scheme.
     *
     * Per RFC 9110 §4.2.3, the default port for "http" is 80
     * and for "https" is 443.
     */
    private function isStandardPort(string $scheme, int $port): bool
    {
        return match (strtolower($scheme)) {
            'http' => $port === 80,
            'https' => $port === 443,
            default => false,
        };
    }

    /**
     * Injects the CSRF token and token manager into request attributes.
     *
     * This allows downstream handlers and view layers to:
     * - Retrieve the token for embedding in forms: $request->getAttribute('csrf_token')
     * - Access the manager for advanced use: $request->getAttribute('csrf_token_manager')
     */
    private function injectToken(ServerRequestInterface $request): ServerRequestInterface
    {
        $token = $this->tokenManager->getActive() ?? $this->tokenManager->generate();

        return $request
            ->withAttribute(self::ATTR_TOKEN, $token)
            ->withAttribute(self::ATTR_TOKEN_MANAGER, $this->tokenManager);
    }

    /**
     * Creates a 403 Forbidden response.
     *
     * Per RFC 9110 §15.5.4, the 403 status code indicates that the
     * server understood the request but refuses to fulfill it.
     * The response body is intentionally generic to avoid leaking
     * information about why validation failed.
     *
     * @see RFC 9110 §15.5.4 - 403 Forbidden
     */
    private function forbidden(string $reason): ResponseInterface
    {
        $response = $this->responseFactory->createResponse(403);
        $body = $response->getBody();
        $body->write('403 Forbidden');

        // Log-friendly reason header (not exposed to browsers in typical setups)
        return $response->withHeader('X-CSRF-Failure', $reason);
    }
}
