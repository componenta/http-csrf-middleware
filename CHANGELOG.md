# Changelog

## Unreleased

### Fixed
- Excluded paths now bypass CSRF before safe-method token injection, matching the documented contract for webhook-style exclusions on every HTTP method.

### Added
- Optional `targetOrigin` lets deployments pin Origin/Referer validation to a trusted server-side HTTP(S) origin instead of deriving the target from the incoming request URI.

### Documentation
- Clarified that RFC 9110 safe methods must not be used for requested state changes.
- Updated cookie guidance to RFC 10025, which obsoletes RFC 6265 and standardizes the `__Host-` prefix constraints used by the legacy cookie manager.

## v3.0.1

Security-compatibility patch release.

### Fixed
- Unknown future `Sec-Fetch-Site` values are ignored as recommended by OWASP for forward compatibility instead of causing a hard 403.
- Unknown Fetch Metadata never bypasses the existing Origin/Referer and CSRF-token validation layers.
- Successful unsafe responses now emit cache-correct `Vary` fields for the security-context request headers that influence the allow/deny decision.
- Safe-method responses keep their original `Vary` contract.
- HTTP safe-method classification is now case-sensitive as required by RFC 9110; lowercase lookalikes such as `get` no longer bypass unsafe-request CSRF validation.

### Verification
- PHP 8.4 and 8.5, lowest and highest dependency sets.
- Composer strict validation and security audit.
- PHPStan level max over source and tests.
- Strict PHPUnit configuration.
- Infection mutation coverage 100%; covered-code MSI 81%.

## v3.0.0

Breaking security-focused release.

### Security
- Unsafe requests now fail closed when both `Origin` and `Referer` are missing unless `allowMissingOrigin: true` is explicitly configured.
- Added strict serialized-origin/request-origin parsing and exact trusted-origin validation.
- Added Fetch Metadata defense in depth for cross-site unsafe requests.
- Target origin must be safely derivable from the normalized PSR-7 request URI.
- Excluded paths are path-segment aware and reject unsafe root/empty configuration.
- Multiple CSRF token header values are rejected.
- Generic CSRF failures are non-cacheable and no longer expose detailed failure reasons by default.
- Native-session CSRF tokens enforce the generated 256-bit lowercase-hex format.
- Legacy cookie CSRF manager is constrained to `__Host-` semantics: Secure, Path=/, and no Domain attribute.

### Compatibility
- Requires `psr/http-factory ^1.1`.
- Test implementation floor is `nyholm/psr7 ^1.8.2` for PHP 8.4 compatibility.
- Existing non-browser clients that omit both Origin and Referer must opt in with `allowMissingOrigin: true`.
- Legacy cookie integrations must migrate to a `__Host-` cookie name and host-only scope.

### Verification
- PHP 8.4 and 8.5, lowest and highest dependency sets.
- Composer strict validation and security audit.
- PHPStan level max over source and tests.
- Strict PHPUnit configuration.
- Infection mutation coverage 100%, covered-code MSI 82%.
