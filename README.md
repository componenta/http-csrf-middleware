# Componenta HTTP CSRF Middleware

CSRF token managers and PSR-15 middleware for PHP 8.4+. The package checks tokens
on unsafe HTTP methods, with optional Origin/Referer checks. Authentication,
session ownership, body parsing, CORS and routing belong to the application.

## Installation

```bash
composer require componenta/http-csrf-middleware
```

This package has no config provider. Supply a token manager and a PSR-17 response
factory explicitly.

## Token managers

| Manager | Context and storage |
|---|---|
| `SessionCsrfTokenManager` | Random token in native PHP `$_SESSION`. Starts a session when needed and fails if storage cannot be opened. |
| `HmacCsrfTokenManager` | Signed token with mandatory trusted session binding; no token storage. |
| `CookieCsrfTokenManager` | Legacy unsigned double-submit cookie using `setcookie()`. |

For Auth 3, use `AuthSessionCsrfTokenManager` and `AuthSessionCsrfMiddleware` from
`componenta/auth-session-http`. They derive tokens from the authenticated session
UUID and credential generation.

The legacy cookie manager does **not** prevent cookie-injection attacks. Do not
choose it for new integrations; use a native session or session-bound HMAC manager.
It uses native response headers, so it is not a PSR-7 cookie transport.

## Session-bound HMAC

```php
use Componenta\Http\Middleware\Csrf\CsrfMiddleware;
use Componenta\Http\Middleware\Csrf\HmacCsrfTokenManager;

// Resolve these from authenticated server-side state, not submitted request data.
$tokens = new HmacCsrfTokenManager(
    secretKey: $csrfKey,
    sessionBinding: $authenticatedSessionId . ':' . $credentialGeneration,
    ttl: 3600,
);
$middleware = new CsrfMiddleware($tokens, $responseFactory);
```

Use a cryptographically random server key of at least 32 bytes. The binding must
identify the current session, change at each new login and at the credential
rotations that should invalidate CSRF tokens, and be resolved independently of
the submitted token. A static user ID, email or tenant ID is insufficient.
For pre-login flows, use a trusted browser-bound pre-authentication transaction
instead of a shared constant.

Construct the manager for each request/session. Never retain a manager as a
singleton across users or reuse it after changing the session. The package
cannot infer session revocation: authenticate and validate the current session
before creating the manager.

Tokens use `v2.nonce.timestamp.mac`. The MAC includes an unambiguous encoding of
the binding and a protocol-specific prefix; the binding itself is not disclosed
in the token. Another session or credential generation cannot validate the token.
Malformed, tampered, expired and legacy unbound tokens are rejected. TTL is a
positive number of seconds; exactly TTL seconds old remains valid, while a token
over 30 seconds in the future is rejected. The optional `clock` closure must
return a positive integer Unix timestamp.

This session-binding requirement follows the
[OWASP CSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#signed-double-submit-cookie-recommended).

## Middleware behavior

Safe methods (`GET`, `HEAD`, `OPTIONS`, `TRACE`) do not validate submitted tokens.
Unsafe methods use `X-CSRF-Token` first, otherwise parsed body field `_csrf_token`.
An invalid nonempty header cannot fall back to a valid body token.

For a form or client request, obtain the token from the injected request attribute
`csrf_token` and submit it explicitly in the header or body. The manager is also
available as `csrf_token_manager`. Never put CSRF tokens in URLs or logs.

`checkOrigin` defaults to `true`. When both Origin and Referer are absent, token
validation still applies. `trustedOrigins` adds explicit allowed origins.
`excludedPaths` exempts configured path prefixes; use it only for routes protected
by a separate authentication mechanism, such as verified provider webhooks.

An invalid/missing token or rejected origin returns HTTP 403 without calling the
protected handler. Invalid server configuration and storage/clock failures raise
exceptions; they are not converted into successful requests.

## Manager contract and native storage

All managers implement `CsrfTokenManagerInterface`:

- `generate()` provides a token; a stored-token manager may replace its previous
  token, while a keyed session implementation may return a stable token.
- `getActive()` obtains a usable token without creating or rotating token state,
  or returns `null`. A keyed implementation can derive it on demand.
- `validate()` checks the submitted token for the current context.

Native-session tokens use `_csrf_token` by default. Reuse `getActive()` when
rendering more forms; calling `generate()` invalidates the previous stored token.
Non-string/empty session values are unavailable. Native session startup failures
throw `RuntimeException`.

The legacy cookie defaults are `csrf_token`, TTL 7200, path `/`, no domain,
`Secure`, `HttpOnly` and `SameSite=Strict`. SameSite accepts Strict/Lax/None
case-insensitively; None requires Secure. TTL must be positive. Malformed cookies
are unavailable, and generation replaces the current request's cached token.
`clear()` expires the cookie and clears that cache. Headers must still be writable;
a failed `setcookie()` raises `RuntimeException`.

## Migration to 2.0

The constructor is now `(secretKey, ttl, sessionBinding, clock = null)`.
TTL and the binding are required. Keeping TTL in its original position prevents
weakly typed old calls from turning an integer TTL into a shared binding.
Old two-argument calls fail with `ArgumentCountError`; old three-argument
calls with a clock closure or `null` fail with `TypeError`.
Replace `new HmacCsrfTokenManager($key, $ttl)` with named arguments including the
trusted binding. Old tokens are intentionally invalid and must be obtained again
from a form/token response. There is no compatibility mode accepting unbound
signatures. The `CsrfTokenManagerInterface` method signatures and Auth 3's existing
session-bound manager remain compatible.
