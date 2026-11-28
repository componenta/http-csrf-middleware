# Componenta HTTP CSRF Middleware

PSR-15 CSRF protection and token managers for PHP 8.4+.

The package combines a session-bound CSRF token with browser request-context checks. Stateful applications should prefer a synchronizer token or a session-bound HMAC token. SameSite cookies and Fetch Metadata are defense-in-depth controls, not replacements for a CSRF token.

## Installation

```bash
composer require componenta/http-csrf-middleware
```

The package has no config provider. Construct the middleware and a PSR-17 response factory explicitly.

## Recommended token managers

| Manager | Use |
|---|---|
| `HmacCsrfTokenManager` | Stateless token signed with a server secret and bound to trusted session state. |
| `SessionCsrfTokenManager` | Session-bound synchronizer token stored in Componenta Session (optional `componenta/session` integration). |
| `NativeSessionCsrfTokenManager` | Session-bound synchronizer token stored in a native PHP session. |
| `CookieCsrfTokenManager` | Legacy double-submit mode only; deprecated for new integrations. |

For Auth 3 browser sessions use `AuthSessionCsrfTokenManager` / `AuthSessionCsrfMiddleware` from `componenta/auth-session-http`. They bind the token to the authenticated session UUID and credential generation.

## Session-bound HMAC

```php
$tokens = new HmacCsrfTokenManager(
    secretKey: $csrfKey,
    ttl: 3600,
    sessionBinding: $authenticatedSessionId . ':' . $credentialGeneration,
);

$middleware = new CsrfMiddleware(
    tokenManager: $tokens,
    responseFactory: $responseFactory,
);
```

Requirements:

- use a cryptographically random server key of at least 32 bytes;
- derive `sessionBinding` from trusted server-side session state;
- change the binding on login/session rotation and credential generations that must invalidate CSRF tokens;
- never derive the binding from submitted request data;
- create the manager for the current request/session context, not as a cross-user singleton.

Tokens use `v2.nonce.timestamp.mac`. The binding is covered by the MAC but is not disclosed in the token. Validation uses constant-time comparison, rejects malformed/legacy tokens, enforces TTL, and permits at most 30 seconds of future clock skew.

## Middleware security model

Unsafe methods require all enabled layers to pass:

1. Fetch Metadata policy;
2. Origin/Referer verification;
3. CSRF token verification.

Safe RFC methods `GET`, `HEAD`, `OPTIONS`, and `TRACE` do not require a submitted token and receive the active/generated CSRF token as a request attribute. HTTP method tokens are case-sensitive: lowercase lookalikes such as `get` are treated as custom unsafe methods and must pass CSRF validation.

This classification follows RFC 9110 semantics. Application routes using a safe method **must not perform requested state-changing actions**; a state-changing `GET` is an HTTP contract violation and is outside the protection boundary of this middleware. OWASP likewise recommends not using `GET` for state changes.

### Fetch Metadata

`checkFetchMetadata` defaults to `true`.

Unsafe requests with:

```http
Sec-Fetch-Site: cross-site
```

are rejected before token validation unless their `Origin` is listed explicitly in `trustedOrigins`.

Recognized values are:

- `same-origin`;
- `same-site`;
- `cross-site`;
- `none`.

Unknown future `Sec-Fetch-Site` values are ignored for forward compatibility; the request still has to pass the configured Origin/Referer and CSRF-token checks.

Fetch Metadata is browser-controlled defense in depth. It does not replace the CSRF token and can be absent on legacy/non-browser clients. Successful unsafe responses add `Vary: Origin, Referer, Sec-Fetch-Site` for the checks that are enabled, while preserving `Vary: *`.

### Origin and Referer

`checkOrigin` defaults to `true`.

The middleware prefers `Origin`; only when it is absent does it fall back to `Referer`. Empty or multiple values of the selected singleton header are malformed, not missing. Both are compared as exact origins including scheme, host, and effective port.

The following fail closed:

- malformed `Origin` / `Referer`;
- `Origin: null`;
- target request URI without a trustworthy HTTP(S) scheme/host;
- both `Origin` and `Referer` missing.

For a legacy/non-browser integration that cannot send either source header, the compatibility escape hatch is explicit:

```php
new CsrfMiddleware(
    tokenManager: $tokens,
    responseFactory: $responseFactory,
    allowMissingOrigin: true,
);
```

The CSRF token is still mandatory on unsafe methods.

### Target origin and reverse proxies

When the externally visible application origin is fixed, prefer an explicit trusted server-side target origin:

```php
new CsrfMiddleware(
    tokenManager: $tokens,
    responseFactory: $responseFactory,
    targetOrigin: 'https://shop.example.com',
);
```

`targetOrigin` must be an exact non-opaque HTTP(S) origin. When configured, Origin/Referer checks compare against it instead of deriving the target from the incoming request URI. This follows OWASP guidance to use a trusted configured target origin where possible and avoids making CSRF trust depend on an attacker-influenced Host value or proxy reconstruction.

If the public origin is dynamic, do not read `X-Forwarded-*` directly inside CSRF middleware. Normalize the effective request URI first with `componenta/http-trusted-proxy-middleware`:

```text
TrustedProxyMiddleware
    -> CsrfMiddleware
    -> application
```

Only configured trusted proxies may affect scheme/host/port. With no `targetOrigin`, the CSRF middleware compares the source origin against that normalized PSR-7 URI.

### Trusted origins

`trustedOrigins` is an explicit exact allowlist:

```php
trustedOrigins: [
    'https://app.example.com',
    'https://admin.example.com:8443',
]
```

Entries must be exact HTTP(S) origins. Paths, queries, fragments, userinfo, opaque `null`, and malformed values are rejected during construction.

No suffix/subdomain wildcard matching is performed.

## Token submission

Header submission is preferred:

```http
X-CSRF-Token: <token>
```

HTML forms may submit:

```text
_csrf_token=<token>
```

If the configured header is present, it has precedence over the body. An empty, invalid, or multiply-specified token header cannot fall back to a valid body token.

CSRF tokens must not be placed in URLs or logs.

## Excluded paths

`excludedPaths` is intended only for endpoints protected by a different trust mechanism, such as signed webhooks.

Matching is path-segment aware:

```php
excludedPaths: ['/webhook']
```

matches:

- `/webhook`;
- `/webhook/provider`;

but not:

- `/webhook-admin`.

Empty, root-only, query-bearing, fragment-bearing, and path-confusing exclusions are rejected. Exclusion matching fails closed for ambiguous request paths such as literal dot segments, backslashes, NULs, encoded path separators/dot segments, and their repeatedly percent-encoded forms. This prevents a proxy/router normalization mismatch from turning a webhook-style exemption into a CSRF bypass. Excluded requests that pass these checks bypass CSRF entirely and do not receive token attributes.

## Failure responses

Rejected requests receive 403 plus:

```http
Cache-Control: no-store
Pragma: no-cache
```

Detailed reasons are not exposed by default.

For local diagnostics only:

```php
debugFailureHeader: true
```

adds `X-CSRF-Failure`.

## Native PHP session manager

`NativeSessionCsrfTokenManager` stores a 32-byte random token as 64 lowercase hex characters, together with a binding to the current native PHP session identifier. A changed session identifier invalidates the old token, even if the session data was retained. Malformed or previously stored unbound token strings are treated as unavailable; existing forms must obtain a fresh token after upgrading.

The manager starts the native PHP session when needed and throws if session storage cannot be opened. It uses PHP's native session API and is intended for a runtime that manages that session lifecycle.

```php
use Componenta\Http\Middleware\Csrf\NativeSessionCsrfTokenManager;

$tokens = new NativeSessionCsrfTokenManager();
```

Session identifier rotation/fixation prevention remains the responsibility of the authentication/session layer. If an authentication handler regenerates the session ID, obtain a new CSRF token for subsequent forms; the token issued before rotation is no longer valid.

## Legacy cookie manager

`CookieCsrfTokenManager` is deprecated for new code. It is an unsigned double-submit pattern and should be replaced with the session or HMAC managers.

To reduce cookie-injection risk, its cookie is now constrained to `__Host-` semantics:

- cookie name must start with `__Host-`;
- `Secure=true`;
- `Path=/`;
- no `Domain` attribute.

The default name is `__Host-csrf_token`.

These constraints follow the current cookie standard, RFC 10025 (July 2026), which obsoletes RFC 6265 and defines `__Host-` as Secure, host-only, and `Path=/`. SameSite remains defense in depth; the CSRF token is still required.

## Verification

GitHub Actions verifies:

- PHP 8.4 and 8.5;
- lowest and highest supported dependencies;
- `composer validate --strict`;
- `composer audit`;
- PHPStan level max for `src` and `tests`;
- PHPUnit security regression tests.

## References

- OWASP Cross-Site Request Forgery Prevention Cheat Sheet;
- RFC 9110 safe-method and HTTP semantics;
- RFC 6454 origin semantics;
- RFC 10025 cookie security and `__Host-` prefix semantics;
- Fetch Metadata request-header guidance;
- OWASP path-confusion/canonicalization guidance for security-relevant path matching.

## Long-running workers

A shared `CsrfMiddleware` can receive a closure instead of a fixed token manager. The closure receives the current PSR-7 request and must return a manager bound to its trusted session context; it is invoked once per non-excluded request after applicable origin checks. Do not retain request-specific managers in shared services. The `csrf_token_manager` request attribute is deprecated; set `exposeTokenManager: false` to remove it now. It defaults to true for existing integrations. Excluded path prefixes must be plain paths: percent escapes, semicolons, repeated slashes, control characters, and dot segments are rejected both at configuration and matching time.


## Componenta Session manager

Install the optional integration with `composer require componenta/session`. Run SessionMiddleware before CSRF and explicitly configure the middleware using the request-scoped resolver:

```php
use Componenta\Http\Middleware\Csrf\SessionCsrfTokenManager;
use Componenta\Http\Middleware\Csrf\CsrfMiddleware;

$csrf = new CsrfMiddleware(
    SessionCsrfTokenManager::fromRequest(...),
    $responseFactory,
    targetOrigin: 'https://shop.example',
    exposeTokenManager: false,
);
```

`SessionCsrfTokenManager` accepts a `Componenta\Session\SessionInterface` in its constructor or resolves it from the current PSR-7 request using `fromRequest()`. It stores a random synchronizer token in the current server-side session. A changed session ID invalidates the old token even when the session data survives regeneration. The session layer must securely create, persist and regenerate identifiers and must isolate session data. This adapter does not replace the separate Auth session integration. Use a session store that prevents lost updates if concurrent first requests must receive the same token.

Responses that actually expose a per-session token must not be stored in shared caches: set `Cache-Control: private, no-store` on those responses. Do not treat `Vary: Origin` as a substitute for session-specific cache isolation.

The legacy cookie manager rejects lifetimes that cannot be represented as a native PHP cookie expiry (including integer overflow or an expiry after year 9999).

## Migration to 4.x

Use `Componenta\Http\Origin` from `componenta/http` 2.x instead of the former CSRF-local class. For PSR-7 requests, pass URI scheme, host and port to `Origin::fromComponents()`. CSRF authorization and token policies remain in this package.
