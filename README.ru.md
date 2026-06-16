# Componenta HTTP CSRF Middleware

Менеджеры CSRF-токенов и PSR-15 промежуточный обработчик для HTTP-приложений Componenta. Обработчик проверяет небезопасные HTTP-методы через валидацию токена и необязательную проверку `Origin`/`Referer`.

## Граница пакета

Пакет отвечает только за выпуск, чтение и проверку CSRF-токенов. Разбор тела запроса, CORS, аутентификация и маршрутизация подключаются отдельными пакетами.

## Установка

```bash
composer require componenta/http-csrf-middleware
```

У пакета нет провайдера конфигурации. Настраивайте менеджер токенов и промежуточный обработчик явно.

## Менеджеры токенов

| Класс | Хранилище |
|---|---|
| `SessionCsrfTokenManager` | PHP `$_SESSION`; при необходимости запускает сессию и по умолчанию хранит токен в ключе `_csrf_token`. |
| `CookieCsrfTokenManager` | Значение cookie, записываемое через `setcookie()`. |
| `HmacCsrfTokenManager` | Stateless HMAC-токен с секретом и необязательным источником активного токена. |

Все менеджеры реализуют `CsrfTokenManagerInterface`.

## Промежуточный обработчик

```php
use Componenta\Http\Middleware\Csrf\CsrfMiddleware;
use Componenta\Http\Middleware\Csrf\SessionCsrfTokenManager;

$middleware = new CsrfMiddleware(
    tokenManager: new SessionCsrfTokenManager(),
    responseFactory: $responseFactory,
    excludedPaths: ['/webhook'],
);
```

Безопасные методы (`GET`, `HEAD`, `OPTIONS`, `TRACE`) не проверяются. Для небезопасных методов токен сначала читается из заголовка `X-CSRF-Token`, затем из поля разобранного тела запроса `_csrf_token`.

Активный токен и менеджер добавляются в атрибуты запроса `csrf_token` и `csrf_token_manager`.

`InvalidCsrfTokenException` промежуточный обработчик превращает в общий ответ 403.
