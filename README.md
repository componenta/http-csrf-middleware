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
| `SessionCsrfTokenManager` | 256-bit random synchronizer token stored in a native PHP session. |
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

Safe RFC methods `GET`, `HEAD`, `OPTIONS`, and `TRACE` do not require a submitted token and receive the active/generated CSRF token as a request attribute.

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

Fetch Metadata is browser-controlled defense in depth. It does not replace the CSRF token and can be absent on legacy/non-browser clients. Successful unsafe responses add `Vary: Origin, Sec-Fetch-Site` for the checks that are enabled, while preserving `Vary: *`.

### Origin and Referer

`checkOrigin` defaults to `true`.

The middleware prefers `Origin`; when it is absent it falls back to `Referer`. Both are compared as exact origins including scheme, host, and effective port.

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

### Reverse proxies

Do not read `X-Forwarded-*` directly inside CSRF middleware.

When the application is behind a reverse proxy, normalize the effective request URI first with `componenta/http-trusted-proxy-middleware`:

```text
TrustedProxyMiddleware
    -> CsrfMiddleware
    -> application
```

Only configured trusted proxies may affect scheme/host/port. The CSRF middleware then compares source origin against the normalized PSR-7 URI.

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

Empty, root-only, query-bearing, and fragment-bearing exclusions are rejected. Excluded requests bypass CSRF entirely and do not receive token attributes.

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

## Native session manager

`SessionCsrfTokenManager` stores a 32-byte random token as 64 lowercase hex characters. Stored session values that do not match this format are treated as unavailable.

The manager starts the native PHP session when needed and throws if session storage cannot be opened.

Session identifier rotation/fixation prevention remains the responsibility of the authentication/session layer.

## Legacy cookie manager

`CookieCsrfTokenManager` is deprecated for new code. It is an unsigned double-submit pattern and should be replaced with the session or HMAC managers.

To reduce cookie-injection risk, its cookie is now constrained to `__Host-` semantics:

- cookie name must start with `__Host-`;
- `Secure=true`;
- `Path=/`;
- no `Domain` attribute.

The default name is `__Host-csrf_token`.

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
- Fetch Metadata request-header guidance.
