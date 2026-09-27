<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf;

/**
 * Issues and verifies unguessable tokens for the manager's current context.
 *
 * Implementations may store a cryptographically random token or derive a token
 * from trusted session state with a secret key. Compare authenticators in
 * constant time. The application owns the manager's request/session lifetime.
 */
interface CsrfTokenManagerInterface
{
    /**
     * Provides a valid token for the current context.
     * A stored-token implementation may rotate it; a keyed implementation may
     * return a stable token for the current session and credential generation.
     */
    public function generate(): string;

    /** Checks the submitted token against the current context and validity rules. */
    public function validate(#[\SensitiveParameter] string $token): bool;

    /**
     * Returns an available token without creating or rotating token state.
     * A session-bound implementation may derive it without a previous generate
     * call. Returns null when no usable token is available.
     */
    public function getActive(): ?string;
}
