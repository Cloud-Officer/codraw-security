# Code Review — codraw/security

Package: `codraw/security` (namespace `Draw\Component\Security`), reviewed at
`/Users/tlacroix/Sites/localhost/codraw/codraw-security`.

## Fixes applied (2026-07-20)

- **composer.json:** PHP version constraint changed from unbounded `>=8.5` to `^8.5` (version-compatibility debt: prevents a future PHP 9 from installing against this package; no effect on any currently existing PHP version).
- **H1** — `composer.json`: declared the real runtime dependencies. Moved
  `symfony/security-http`, `symfony/security-core`, `symfony/translation-contracts`
  (widened to `^2.5 || ^3.0` to match what Symfony 6.4 apps install) and
  `firebase/php-jwt` from `require-dev` to `require`; added
  `symfony/event-dispatcher`, `symfony/http-foundation`, `symfony/http-kernel`
  (`^6.4.0`). Added a `suggest` section for the optional, config-gated
  integrations: `codraw/messenger` (MessageAuthenticator), `symfony/console` /
  `symfony/messenger` (system authenticator listeners),
  `symfony/security-bundle` and `codraw/framework-extra-bundle` (DI
  integration/factories). `composer validate --no-check-publish` passes.
- **H2** — `Http/Authenticator/JwtAuthenticator.php`: `getToken()` now catches
  `\UnexpectedValueException|\DomainException|\InvalidArgumentException`, so a
  structurally malformed bearer token is treated as "no token" instead of
  producing a 500. (The second decode in `authenticate()` is only reachable
  after `getToken()` has just decoded the same token successfully, so it is
  covered by the same guard path.)
- **M1** — `Http/Authenticator/MessageAuthenticator.php`: `getMessageUser()`
  now catches `UserNotFoundException` from
  `UserProviderInterface::loadUserByIdentifier()` and returns `null`, so a
  message whose user was deleted no longer 500s during `supports()`.
- **M2** — `Http/Authenticator/MessageAuthenticator.php`: constructor now
  type-hints `Draw\Contracts\Messenger\EnvelopeFinderInterface` instead of the
  concrete `EnvelopeFinder`, matching the `Reference` injected by
  `MessengerMessageAuthenticatorFactory` (pure widening — the concrete class
  implements the interface, so existing wiring is unaffected).
- **M3** — `Http/EventListener/RoleRestrictedAuthenticatorListener.php`: a
  passport carrying a `RoleRestrictedBadge` without a `UserBadge` now fails
  closed with a clean `CustomUserMessageAuthenticationException('Access
  denied.')` instead of a null-pointer `Error`.
- **L1** — `Jwt/JwtEncoder.php`: `encode()` now throws a descriptive
  `\RuntimeException` when `openssl_pkey_get_private()` returns `false`,
  instead of passing `false` to `JWT::encode()`. (The per-call re-parsing /
  caching suggestion was not applied.)

Validation pass (2026-07-20): `composer install` resolves and installs cleanly
with the corrected `composer.json` (a fresh `composer.lock` was generated
locally; not committed). Full test suite: 70 tests, 243 assertions, 0
failures/errors (exit code 0) — identical with and without the fixes (verified
via `git stash`), including 48 pre-existing PHPUnit 12 "mock without
expectations" notices in test files this pass did not touch. PHPStan (level 5,
empty baseline) reports 11 errors, all pre-existing and byte-identical with
and without the fixes (verified via `git stash`): 8 × missing
`symfony/security-bundle` classes referenced by the optional DI factories
(`DependencyInjection/Factory/*AuthenticatorFactory.php`,
`DependencyInjection/SecurityIntegration.php` — the bundle has never been a
dependency; it is now listed in `suggest`), and 3 × `return.unusedType` on the
legacy anonymous-class methods in `Core/Authentication/Token/SystemToken.php`
(see L5). `markdownlint-cli2` reports 0 errors. No code changes were needed in
this validation pass.

Not fixed (deliberately out of scope for this pass): M4 (trust-boundary
documentation / expiration enforcement — design decision), L2 (public API
rename — BC break), L3 (403 → 401 — API response change), L4 (payload
caching — performance refactor), L5 (dead-code removal — public methods, BC),
L6 (documentation callout), L7 (claim-handling behavior change).

## Overall assessment

This is a small, focused security component providing a JWT authenticator, a
messenger-message "auto connect" authenticator, a system-user authentication
mechanism (console/messenger workers), an event-driven user-checker decorator,
passport badges, and DI integration for the Draw framework. The code is clean,
classes are small and single-purpose, and unit test coverage is broad. The JWT
handling avoids the classic algorithm-confusion pitfall by pinning the
algorithm via `Firebase\JWT\Key`, and the `JwtPayloadBadge` design (badge must
be fully resolved) is a nice defense-in-depth touch. The main problems are a
packaging defect (no runtime dependencies declared in `composer.json`),
incomplete exception handling around `firebase/php-jwt` (unauthenticated
requests with garbage tokens can produce 500s instead of being ignored), and a
few robustness/typing gaps in the authenticators.

## Findings

### High

#### **[FIXED]** H1. composer.json declares no runtime dependencies

`composer.json:17-33` — the `require` section contains only `"php": ">=8.5"`.
Everything the production code hard-depends on is listed under `require-dev`:
`symfony/security-core`, `symfony/security-http` (`AbstractAuthenticator`,
badges, passports), `symfony/http-foundation`/`http-kernel`
(`Request`, `HttpException` in `Http/Authenticator/JwtAuthenticator.php`),
`symfony/console`, `symfony/messenger`, `symfony/event-dispatcher` contracts,
`symfony/translation-contracts`, `firebase/php-jwt` (`Jwt/JwtEncoder.php`),
and `codraw/messenger` / contracts (`Http/Authenticator/MessageAuthenticator.php`,
`DependencyInjection/Factory/MessengerMessageAuthenticatorFactory.php`).
Installing `codraw/security` standalone yields fatal "class not found" errors
at runtime. Sibling packages (e.g. `codraw/console`, `codraw/validator`)
correctly declare their runtime requires, so this is a defect, not a monorepo
convention. At minimum the symfony/security packages should be in `require`,
with `firebase/php-jwt` and `codraw/messenger` either required or declared in
`suggest` (they are optional features).

#### **[FIXED]** H2. Malformed JWT can produce a 500 instead of being treated as "no token"

`Http/Authenticator/JwtAuthenticator.php:91-97` — `getToken()` catches only
`\UnexpectedValueException` around `$this->encoder->decode($token)`.
`firebase/php-jwt` v6 also throws `\DomainException` (from
`JWT::jsonDecode()` / `handleJsonError()` when a base64-decoded segment is not
valid JSON, and for unsupported algorithms / OpenSSL errors) and
`\InvalidArgumentException` (empty key). Since `supports()` (line 33-36) calls
`getToken()` on every request for the firewall, an unauthenticated client
sending `Authorization: Bearer xx.yy.zz` where the segments decode to non-JSON
binary triggers an uncaught `DomainException` → HTTP 500, instead of the
authenticator simply not supporting the request (401). This is both an
error-semantics bug and a trivially reachable noise/DoS vector for error
reporting. Fix: catch `\UnexpectedValueException|\DomainException|\InvalidArgumentException`
(or `\Throwable` narrowed sensibly) in `getToken()`, and equally guard the
second decode in `authenticate()` (line 108).

### Medium

#### **[FIXED]** M1. MessageAuthenticator::supports() can throw for deleted users

`Http/Authenticator/MessageAuthenticator.php:57-74` — `getMessageUser()`
catches `MessageNotFoundException` but calls
`$this->userProvider->loadUserByIdentifier(...)` (line 73) unguarded.
`UserProviderInterface::loadUserByIdentifier()` throws `UserNotFoundException`
when the user does not exist. Because `getMessageUser()` is invoked from
`supports()` (line 34), a stored message whose user has since been deleted
makes every request carrying that `dMUuid` fail with an uncaught exception
(500) during the *supports* phase, before Symfony's authentication error
handling applies. Catch `UserNotFoundException` and return `null`.

#### **[FIXED]** M2. Concrete/interface type mismatch between MessageAuthenticator and its DI factory

`Http/Authenticator/MessageAuthenticator.php:24` type-hints the concrete
`Draw\Component\Messenger\Searchable\EnvelopeFinder`, while
`DependencyInjection/Factory/MessengerMessageAuthenticatorFactory.php:41`
injects `new Reference(Draw\Contracts\Messenger\EnvelopeFinderInterface::class)`.
This only works while the interface alias happens to point at the concrete
class; any consumer binding the contract to another implementation (or a
decorator) gets a `TypeError` at container instantiation time. The
authenticator should type-hint `EnvelopeFinderInterface` — the contract exists
precisely for this.

#### **[FIXED]** M3. RoleRestrictedAuthenticatorListener assumes a UserBadge is always present

`Http/EventListener/RoleRestrictedAuthenticatorListener.php:31` —
`$passport->getBadge(UserBadge::class)->getUser()` will fatal with a null
pointer if a passport carries a `RoleRestrictedBadge` without a `UserBadge`
(`getBadge()` returns `?BadgeInterface`). All of Symfony's built-in passports
include a `UserBadge`, but this listener is a generic extension point for
custom authenticators; a missing badge should produce a clean
`AuthenticationException`, not a `TypeError`. Also note `getUser()` itself can
return a user whose roles are empty — the `in_array` check then denies, which
is correct, but the null-badge path is not.

#### M4. Message-link authentication is a bearer capability in the query string

`Http/Authenticator/MessageAuthenticator.php:34,41` — possession of a message
UUID passed as a query parameter (`dMUuid`) is sufficient to fully
authenticate as the message's user. Expiration is only enforced indirectly by
`EnvelopeFinder`'s default `ExpirationStamp` filter (messages without that
stamp never expire), the link is multi-use (nothing consumes the message at
this layer), and query strings routinely leak via access logs, proxies,
browser history, and `Referer` headers. This is inherent to the "click a link
in an email to auto-login" feature, but the trust boundary deserves a
documented warning, and message producers should be strongly encouraged (or
forced) to attach expiration stamps for anything implementing
`AutoConnectInterface`.

### Low

#### **[FIXED]** L1. `openssl_pkey_get_private()` failure is not checked

`Jwt/JwtEncoder.php:22-24` — if the configured private key or passphrase is
wrong, `openssl_pkey_get_private()` returns `false`, which is then passed to
`JWT::encode()`, producing a confusing downstream `TypeError`/`DomainException`
instead of a clear configuration error. Check for `false` and throw a
descriptive exception. (The key is also re-parsed on every `encode()` call —
harmless at low volume, but worth caching.)

#### L2. `generaToken()` — misspelled public API method

`Http/Authenticator/JwtAuthenticator.php:43` — public method `generaToken()`
(should be `generateToken()`). Renaming is a BC break at this point, but the
typo is baked into the public surface of a security component and is worth a
deprecation-then-rename cycle.

#### L3. Authentication failure returns 403 instead of 401

`Http/Authenticator/JwtAuthenticator.php:127-130` —
`onAuthenticationFailure()` throws an `HttpException` with
`Response::HTTP_FORBIDDEN` (403). RFC 7235 semantics for a missing/invalid
credential are 401 with a `WWW-Authenticate` challenge; 403 means
"authenticated but not allowed". Clients distinguishing "re-login needed" from
"permission denied" will misbehave.

#### L4. JWT decoded up to three times per authenticated request

`Http/Authenticator/JwtAuthenticator.php:33-36,100-108` — `supports()` decodes
the token (via `getToken()`), then `authenticate()` calls `getToken()` again
(second decode) and `decode()` a third time. Signature verification is not
free (especially RS256). Cache the decoded payload per request, or decode once
in `authenticate()`.

#### L5. Dead/legacy code in SystemToken

`Core/Authentication/Token/SystemToken.php:49-52` — `isAuthenticated()`
overrides nothing in Symfony 6 (`TokenInterface::isAuthenticated()` was
removed in 6.0), and the anonymous user's `getSalt()`/`getUsername()`
(lines 33-45) correspond to interfaces removed in Symfony 6. Harmless, but
misleading leftovers that suggest behavior (an "authenticated" flag) that no
longer exists.

#### L6. AbstainRoleHierarchyVoter changes deny semantics — document the interaction

`Core/Authorization/Voter/AbstainRoleHierarchyVoter.php:11-16` together with
`DependencyInjection/SecurityIntegration.php:139-145` — when enabled, the core
`security.access.role_hierarchy_voter` alias is replaced with a voter that
converts `ACCESS_DENIED` into `ACCESS_ABSTAIN`. Under the default affirmative
strategy this is fine, but combined with
`access_decision_manager.allow_if_all_abstain: true` it silently grants access
that the stock voter would have denied. The feature is opt-in, but this
interaction should be called out in documentation.

#### L7. JwtPayloadBadge ignores only exp/nbf/iat

`Http/Authenticator/Passport/Badge/JwtPayloadBadge.php:9-13` — tokens carrying
other standard registered claims (`iss`, `aud`, `sub`, `jti`) produce an
unresolved badge and thus fail authentication unless an application listener
resolves each key. Strictness is a reasonable default, but tokens minted by
common third-party libraries include these claims routinely; the resulting
failure ("badge not resolved") is hard to diagnose. Consider ignoring (or
validating) the full RFC 7519 registered-claims set, or documenting the
requirement.

## Strengths

- **Algorithm pinning**: `JwtEncoder::decode()` (`Jwt/JwtEncoder.php:35`) uses
  `new Key($this->key, $this->algorithm)`, so the token's `alg` header cannot
  downgrade or confuse verification; the integration config additionally
  restricts the algorithm enum (`DependencyInjection/SecurityIntegration.php:209`).
- **Strict payload handling**: `JwtPayloadBadge` must be explicitly resolved
  key-by-key, so unexpected claims cannot be silently ignored — unresolved
  badges fail the passport. A thoughtful fail-closed design.
- **Role-restricted authentication** via `RoleRestrictedBadge` +
  `RoleRestrictedAuthenticatorListener` cleanly reuses the role hierarchy and
  fails closed with a generic "Access denied." message (no information leak).
- **Message expiry at the right layer**: `EnvelopeFinder` applies an
  `ExpirationStamp` filter by default, so expired auto-connect links are
  rejected before user loading.
- **Good DI hygiene**: opt-in features (`canBeEnabled()` everywhere),
  definitions removed when disabled, user-checker decoration done with a
  proper compiler pass (`DependencyInjection/Compiler/UserCheckerDecoratorPass.php`)
  that no-ops when security isn't installed.
- **Clean, small classes** with constructor property promotion, readonly-style
  immutability in events, and an empty phpstan baseline.
- The JWT authenticator loads the user in `authenticate()` only, not in
  `supports()` — correct phase separation (unlike M1 in the message
  authenticator).

## Test coverage

Coverage breadth is good: 14 test files (~3,300 lines) against ~19 source
classes, with dedicated unit tests for `JwtEncoder` (round-trip, expiry, wrong
key), `JwtAuthenticator` (supports/no-token/invalid-token, token generation,
authenticate success/failure paths, translator behavior),
`MessageAuthenticator` (connected/unconnected user, message-not-found,
non-auto-connect messages), `EventDrivenUserChecker`, both system
authenticator listeners (console option handling, messenger auto-login),
both badges, `RoleRestrictedAuthenticatorListener`, the
`UserCheckerDecoratorPass`, and a full `SecurityIntegrationTest` for the DI
configuration tree and service registration.

Gaps:

- No tests for `SystemAuthenticator` / `SystemToken` themselves (only their
  listeners), `AbstainRoleHierarchyVoter`, or the `Core/Security.php` facade.
- The two authenticator factories
  (`DependencyInjection/Factory/JwtAuthenticatorFactory.php`,
  `MessengerMessageAuthenticatorFactory.php`) have no tests — the firewall
  config nodes and service wiring (including the M2 interface/concrete
  mismatch) are unverified.
- No test feeds a *structurally malformed* (non-JSON-segment) token through
  `JwtAuthenticator::supports()` — exactly the H2 gap; the existing test mocks
  the encoder and only simulates `UnexpectedValueException`.
- RS256/private-key encoding path in `JwtEncoder` is untested (tests cover
  HS256 only).
