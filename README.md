# Componenta HTTP CSRF Middleware

CSRF token managers and PSR-15 middleware for Componenta HTTP applications. The middleware checks unsafe methods with token validation and optional Origin/Referer verification.

## Installation

```bash
composer require componenta/http-csrf-middleware
```

This package has no config provider. Configure the token manager and middleware explicitly.

## Token Managers

| Class | Storage |
|---|---|
| `SessionCsrfTokenManager` | PHP `$_SESSION`; starts the session when needed and stores the token under `_csrf_token` by default. |
| `CookieCsrfTokenManager` | Cookie value written through `setcookie()`. |
| `HmacCsrfTokenManager` | Stateless HMAC token with a secret and optional active token source. |

All managers implement `CsrfTokenManagerInterface`.

## Middleware

```php
use Componenta\Http\Middleware\Csrf\CsrfMiddleware;
use Componenta\Http\Middleware\Csrf\SessionCsrfTokenManager;

$middleware = new CsrfMiddleware(
    tokenManager: new SessionCsrfTokenManager(),
    responseFactory: $responseFactory,
    excludedPaths: ['/webhook'],
);
```

Safe methods (`GET`, `HEAD`, `OPTIONS`, `TRACE`) are not validated. Unsafe methods read the token from the `X-CSRF-Token` header first and then from the parsed body field `_csrf_token`.

The active token and manager are added to request attributes `csrf_token` and `csrf_token_manager`.

`InvalidCsrfTokenException` is converted by the middleware into a generic 403 response.
