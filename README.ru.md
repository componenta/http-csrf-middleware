# Componenta HTTP CSRF Middleware

PSR-15 защита от CSRF и token managers для PHP 8.4+.

Пакет сочетает session-bound CSRF token с проверкой браузерного контекста запроса. Для stateful-приложений основной защитой остаётся synchronizer token или HMAC-токен, привязанный к trusted session state. SameSite и Fetch Metadata используются как defense in depth.

## Установка

```bash
composer require componenta/http-csrf-middleware
```

## Рекомендуемые managers

| Manager | Назначение |
|---|---|
| `HmacCsrfTokenManager` | Stateless HMAC-токен, привязанный к доверенному session context. |
| `SessionCsrfTokenManager` | Случайный 256-bit synchronizer token в native PHP session. |
| `CookieCsrfTokenManager` | Только legacy double-submit; для новых интеграций deprecated. |

Для Auth 3 используйте `AuthSessionCsrfTokenManager` / `AuthSessionCsrfMiddleware` из `componenta/auth-session-http`.

## HMAC и session binding

```php
$tokens = new HmacCsrfTokenManager(
    secretKey: $csrfKey,
    ttl: 3600,
    sessionBinding: $sessionId . ':' . $credentialGeneration,
);
```

Требования:

- случайный server secret минимум 32 байта;
- binding только из trusted server-side session state;
- binding меняется при новом login/session rotation и нужных credential rotations;
- binding нельзя брать из request input;
- manager создаётся в контексте текущей session, а не как singleton между пользователями.

Формат токена: `v2.nonce.timestamp.mac`. Session binding не раскрывается, но входит в MAC. Используется constant-time comparison, TTL и ограничение future skew 30 секунд.

## Модель middleware

Для unsafe methods должны пройти все включённые слои:

1. Fetch Metadata;
2. Origin/Referer;
3. CSRF token.

Safe методы RFC `GET`, `HEAD`, `OPTIONS`, `TRACE` не требуют submitted token и получают активный/новый token через request attribute. HTTP method token регистрозависим: lowercase-формы вроде `get` считаются custom unsafe methods и обязаны пройти CSRF validation.

Эта классификация следует семантике RFC 9110. Маршрут с safe method **не должен выполнять запрошенное изменение состояния**; state-changing `GET` нарушает HTTP-контракт и находится вне границы защиты этого middleware. OWASP также рекомендует не использовать `GET` для изменения состояния.

### Fetch Metadata

`checkFetchMetadata=true` по умолчанию.

Unsafe запрос с:

```http
Sec-Fetch-Site: cross-site
```

блокируется до проверки токена, кроме exact origins из `trustedOrigins`.

Поддерживаются `same-origin`, `same-site`, `cross-site`, `none`. Неизвестное будущее значение `Sec-Fetch-Site` игнорируется для forward compatibility; запрос всё равно обязан пройти проверки Origin/Referer и CSRF token.

Fetch Metadata — дополнительная браузерная защита и не заменяет CSRF token. Успешный unsafe-ответ добавляет `Vary: Origin, Sec-Fetch-Site` для включённых проверок и сохраняет `Vary: *` без расширения.

### Origin / Referer

`checkOrigin=true` по умолчанию.

Сначала проверяется `Origin`, при его отсутствии — `Referer`. Сравнение точное: scheme + host + effective port.

Fail-closed:

- malformed Origin/Referer;
- `Origin: null`;
- невозможно безопасно определить target HTTP(S) origin;
- отсутствуют и `Origin`, и `Referer`.

Для legacy/non-browser клиента совместимость включается только явно:

```php
allowMissingOrigin: true
```

CSRF token при этом всё равно обязателен.

### Reverse proxy

CSRF middleware не должно само доверять `X-Forwarded-*`.

Правильный порядок:

```text
TrustedProxyMiddleware
    -> CsrfMiddleware
    -> application
```

`componenta/http-trusted-proxy-middleware` сначала нормализует scheme/host/port только от trusted proxies и удаляет raw forwarding headers.

### Trusted origins

`trustedOrigins` — только exact allowlist:

```php
trustedOrigins: [
    'https://app.example.com',
    'https://admin.example.com:8443',
]
```

Path/query/fragment/userinfo, `null` и malformed values запрещены. Wildcard/suffix matching отсутствует.

## Передача токена

Предпочтительно:

```http
X-CSRF-Token: <token>
```

Для HTML form допускается `_csrf_token`.

Если token header присутствует, он имеет приоритет. Пустой, неверный или переданный несколькими header values токен не может fallback на валидный body token.

Не помещайте CSRF tokens в URL или logs.

## Excluded paths

`excludedPaths` предназначен только для маршрутов с отдельным trust mechanism, например signed webhooks.

```php
excludedPaths: ['/webhook']
```

совпадает с `/webhook` и `/webhook/provider`, но не с `/webhook-admin`.

Пустой path, `/`, query/fragment запрещены. На excluded request CSRF полностью не выполняется и token attributes не добавляются.

## Ошибки

Rejected request получает 403:

```http
Cache-Control: no-store
Pragma: no-cache
```

Причина ошибки наружу по умолчанию не выдаётся. Для локальной диагностики можно явно включить:

```php
debugFailureHeader: true
```

## Session manager

`SessionCsrfTokenManager` хранит случайный 32-byte token в виде 64 lowercase hex символов. Любое другое значение в session считается повреждённым/недоступным.

За rotation session ID и защиту от session fixation отвечает authentication/session layer.

## Legacy cookie manager

`CookieCsrfTokenManager` deprecated для нового кода. Это unsigned double-submit pattern.

Для снижения cookie-injection риска теперь обязательны `__Host-` semantics:

- имя начинается с `__Host-`;
- `Secure=true`;
- `Path=/`;
- `Domain` отсутствует.

Default: `__Host-csrf_token`.

Ограничения соответствуют актуальному RFC 10025 (июль 2026), который заменил RFC 6265 и определяет `__Host-` как Secure, host-only cookie с `Path=/`. SameSite остаётся defense in depth и не заменяет CSRF token.

## Проверка качества

GitHub Actions проверяет PHP 8.4/8.5, lowest/highest dependencies, `composer validate --strict`, `composer audit`, PHPStan level max по `src/tests` и PHPUnit regression tests.

Ориентиры: OWASP CSRF Prevention Cheat Sheet, RFC 9110, RFC 6454, RFC 10025 и Fetch Metadata guidance.
