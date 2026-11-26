<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf;

use Componenta\Session\SessionInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Optional adapter for the session published by componenta/session's
 * SessionMiddleware. Never use an instance across unrelated sessions.
 */
final readonly class SessionCsrfTokenManager implements CsrfTokenManagerInterface
{
    public function __construct(
        private SessionInterface $session,
        private string $sessionKey = '_csrf_token_v2',
    ) {
        if ($sessionKey === '' || strlen($sessionKey) > 256
            || preg_match('/[\x00-\x1f\x7f]/', $sessionKey) === 1) {
            throw new \InvalidArgumentException('CSRF session key is invalid.');
        }
    }

    /**
     * Resolve the trusted request-scoped session. Missing session middleware
     * is a configuration error, not an opportunity to create an unbound token.
     */
    public static function fromRequest(ServerRequestInterface $request): self
    {
        $session = $request->getAttribute(SessionInterface::class);
        if (!$session instanceof SessionInterface) {
            throw new \RuntimeException('Componenta SessionMiddleware must run before CSRF.');
        }
        return new self($session);
    }

    #[\Override]
    public function generate(): string
    {
        $token = bin2hex(random_bytes(32));
        $this->session->data->set($this->sessionKey, [
            'binding' => $this->binding(),
            'token' => $token,
        ]);
        return $token;
    }

    #[\Override]
    public function validate(#[\SensitiveParameter] string $token): bool
    {
        if (!self::validToken($token)) {
            return false;
        }
        $active = $this->getActive();
        return $active !== null && hash_equals($active, $token);
    }

    #[\Override]
    public function getActive(): ?string
    {
        $value = $this->session->data->get($this->sessionKey, null);
        if (!is_array($value) || !isset($value['binding'], $value['token'])
            || !is_string($value['binding']) || !is_string($value['token'])
            || !self::validToken($value['token'])
            || !hash_equals($this->binding(), $value['binding'])) {
            return null;
        }
        return $value['token'];
    }

    /** @return array{session: string} */
    public function __debugInfo(): array
    {
        return ['session' => '[REDACTED]'];
    }

    private function binding(): string
    {
        return hash('sha256', "componenta-session-csrf-v2\0" . (string) $this->session->id);
    }

    private static function validToken(string $token): bool
    {
        return preg_match('/\A[0-9a-f]{64}\z/D', $token) === 1;
    }
}
