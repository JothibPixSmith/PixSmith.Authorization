# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build & restore
dotnet restore
dotnet build OAuthSolution.sln

# Run the auth server (https://localhost:7100)
# This also serves the Blazor WASM admin UI — one process, one port.
# The Blazor project is never launched on its own; it has no API to talk to.
cd src/AuthServer/AuthServer.API && dotnet run

# Tests
dotnet test tests/PixSmith.Authorization.UnitTests
dotnet test tests/PixSmith.Authorization.IntegrationTests

# Debug against Postgres in containers (VS Code: F5 -> "Attach to Auth Server (container)")
./debug/start.sh

# Production-shaped staging stack: Release image, Staging environment, TLS proxy at
# https://localhost:8443. No debugger. Uses podman (CONTAINER_ENGINE=docker to switch).
# The debug stack above still uses docker. See staging/README.md.
./staging/start.sh
```

No lint tooling is configured beyond `<Nullable>enable</Nullable>` and `<ImplicitUsings>enable</ImplicitUsings>` in all projects.

## Architecture

This is an OAuth 2.0 / OIDC authorization server built with **OpenIddict** on **ASP.NET Core + Identity**. It follows Onion Architecture; dependency flow is strictly inward:

```
Domain ← Application ← Infrastructure ← API
                                      ← DataContext ← Repositories ← Services
```

Every project lives under `src/`; tests live under `tests/`. Nothing sits at the repository root.

```
src/
├── AuthServer/                                     API, Domain, Infrastructure
├── BlazorClient/                                   Blazor WASM admin UI, served by the API
├── PixSmith.Authorization.DataContext/
├── PixSmith.Authorization.DataContext.Migrations.Sqlite/
├── PixSmith.Authorization.DataContext.Migrations.Postgres/
├── PixSmith.Authorization.Repositories/
└── PixSmith.Authorization.Services/
```

Note that folder names under `src/AuthServer/` use an `AuthServer.*` prefix while the
projects inside them are named `PixSmith.Authorization.*` — e.g. `AuthServer.API/`
contains `PixSmith.Authorization.API.csproj`.

### Project roles

| Project | Role |
|---|---|
| `PixSmith.Authorization.Domain` | Pure aggregates (`ApplicationUser`, `OAuthClient`), domain events, and `Result<T>` monad — zero external dependencies |
| `AuthServer.Infrastructure` | EF Core + OpenIddict + ASP.NET Identity wiring; `OpenIddictSeeder` hosted service seeds default clients, scopes and roles on startup |
| `PixSmith.Authorization.API` | HTTP entry point — `ConnectController` (OIDC protocol), `AccountController` (login/SSO), `AdminController` (user & client management) |
| `PixSmith.Authorization.DataContext` | `ApplicationDbContext` combining Identity + OpenIddict + custom tables (`UserProfile`, `OAuthClientRegistration`, `AuditLog`) |
| `PixSmith.Authorization.Repositories` | EF Core implementations of `IUserRepository` / `IOAuthClientRepository` |
| `PixSmith.Authorization.Services` | `UserService`, `OAuthClientService`, `PasswordHashingService`, `EmailService` (stub) |
| `BlazorClient` | Blazor WASM admin UI, served by the API at the same origin. Signs in with **authorization code + PKCE** via `AddOidcAuthentication`, redirecting to the server's own login page; `ApiAuthorizationMessageHandler` attaches the token. It never handles a password |

### Key design points

**Two parallel user models.** `ApplicationUser` (Domain) is a framework-free aggregate that tracks login attempts, lockout, roles, external logins, and 2FA state entirely in domain logic. `IdentityUser<Guid>` (ASP.NET Identity) handles the actual persistence and password hashing. They are kept in sync by `UserService`.

**OpenIddict over IdentityServer.** OpenIddict runs in-process, shares the EF Core `DbContext`, and integrates directly with ASP.NET Identity — no separate server process needed.

**PKCE (S256 only) required per client, for every authorization-code client.** There's no server-wide switch. Each such client carries the OpenIddict PKCE requirement, set by `OidcAppService` and backfilled at startup by `PkcePolicy.EnforceAsync`. `plain` is disabled server-wide. The one exception is a client flagged PKCE-exempt for conformance-suite runs. It's honoured only while `Security:AllowPkceExemptClients` is true, and the server refuses to start with that on in Production. The Blazor client (`blazor-client`) is a pre-seeded public client. The M2M client (`m2m-client`) is confidential and uses Client Credentials.

**Error handling via Result<T>.** Domain methods return `Result<T>` instead of throwing exceptions. Infrastructure and service layers map these to HTTP responses in controllers.

**Database migrates on startup.** `Program.cs` calls `db.Database.MigrateAsync()` before the host starts. `Database:Provider` selects SQLite (default, `auth.db`) or Postgres; migrations live in two provider-specific projects and **both must be generated** for any model change, or the other provider fails at runtime.

**Tenancy is enforced.** A user reaches an application when they are an active member of an active company that subscribes to that client — checked at `/connect/authorize`, at device-flow approval, and on every refresh. Tokens carry `org_id`, `org_slug` and a plural `roles` claim (company roles); the singular `role` claim carries platform Identity roles and is separate. `TenantEnforcement:PlatformClients` exempts clients that administer the server itself. See `docs/MULTI-TENANCY.md`.

**Credential endpoints are rate limited.** `/connect/token`, the login form, registration and
password reset are capped per client IP **per endpoint** (default 20/60s, `RateLimiting:*`).
Identity's lockout caps failures against one account; this is what bounds credential stuffing
across many accounts and CPU exhaustion through the password hasher. Buckets are per endpoint so
a flood against one cannot deny the others to the same address.

**Registration cannot be used to enumerate accounts.** `POST /api/account/register` returns a
byte-identical 200 whether or not the address was taken; the real owner is told by email instead.
Password-policy failures are still reported, since they disclose nothing about other accounts.

**The login page executes no JavaScript.** It is served with
`default-src 'none'; style-src 'self'; …` and its styles come from `/css/auth.css` in the API's
own `wwwroot`, not a CDN. If you add a utility class to a view, add the rule to that file — there
is no build step. The Blazor admin UI still loads Tailwind from a CDN, so its CSP is looser.

**There is no password grant.** It was removed: a pen test flagged it, and its only users were
the admin UI (now authorization code + PKCE) and the provisioning scripts. Those now use the
**device authorization grant** (RFC 8628) — `provisioning-cli` requests a code, a human approves
it at `/connect/verify`, and the script polls `/connect/token`. Nothing but the server's own login
page ever receives a password. Integration tests drive the real redirect flow through
`SecurityWebApplicationFactory.GetUserTokenAsync`.

**Device clients must be created through the admin API, which grants both permissions.**
`OidcAppService` adds the device authorization *endpoint* permission alongside the grant — a
client with only `gt:…device_code` is refused at `/connect/deviceauthorization`. It accepts the
short `device_code` alias as well as the RFC 8628 URN. `RegisterClientAsync` in the test factory
talks to the OpenIddict manager directly and deliberately bypasses this, so cover for that code
path has to go through `CreateOidcAppAsync`.

**The password grant cannot be configured, either.** `OidcAppService` refuses it with an
explanatory error rather than silently dropping the permission: a client carrying `gt:password`
would look configured, do nothing, and quietly start working if the grant were ever re-enabled.

**Device-code polling is paced per device code.** `DevicePollingThrottle` answers polls that
arrive inside the interval with `slow_down` (RFC 8628 §3.5), widening that code's required
interval by 5s each time. It is middleware, not controller code, because OpenIddict answers
`authorization_pending` from its own pipeline while a code is pending — `ConnectController` never
sees those polls. Settings live under `DevicePolling:*`.

**Sessions live on the server, not in the cookie.** `EfTicketStore` (an `ITicketStore` backed
by the `AuthenticationTickets` table) means the cookie carries only an opaque key, so logout
revokes the session rather than just deleting the browser's copy — a cookie captured beforehand
stops working immediately.

**The Identity cookie is deliberately *not* the default authenticate scheme.** `AddIdentity`
makes it so, which had `UseAuthentication` reading the cookie — and therefore querying the
session store — on every request that reached the middleware. Because the admin UI is
same-origin the browser attaches that cookie to every `/api/*` call too, none of which use it:
those endpoints authorize with the bearer scheme. The default is pointed at the token validation
scheme instead, measured as one fewer database round-trip per such request. Nothing may rely on
the default: every `[Authorize]` names its scheme (or uses a policy that does), and anything
needing the cookie calls `AuthenticateAsync(IdentityConstants.ApplicationScheme)` explicitly —
`LoginController.LogoutEverywhere` is the one that learned this the hard way, since reading
`User` there would have revoked nothing, silently. The *challenge* scheme is left alone so a
challenge still redirects to the login page.

Do not put a memory cache in front of the ticket store without thinking it through: on more than
one instance, logout on one node leaves a replayed cookie working on another until its entry
expires, which is exactly the window the server-side session exists to close. `AuthenticationTicketCleanup` sweeps expired rows, and
`POST /Account/LogoutEverywhere` deletes every session for the user *and* rotates the security
stamp. `Sessions:*` configures the sweep interval and the stamp revalidation window.

**Signing out everywhere revokes tokens, not just sessions.** A signed-in user holds three
credentials and the cookie is only one. `TokenRevocation` marks every token entry and
authorization for that subject revoked, which is what stops a refresh token outliving the
logout — refresh tokens are checked against storage when redeemed, so this bites at the next
attempt and costs nothing per request. Authorizations are revoked *before* tokens on purpose: a
refresh already in flight validates both, so a request that slips past the token sweep is still
refused. An ordinary `/Account/Logout` deliberately does **not** revoke — ending one browser
session is not a statement about the applications the user authorized — and there is a test
pinning that down.

What remains open is an access token already issued: it is a signed JWT validated against the
key, with no entry consulted, so it stays good until it expires (an hour; the OpenIddict
default, nothing overrides it). Closing that window too means `EnableTokenEntryValidation`,
which buys immediate revocation at one database read per API request — the exact cost that
pointing the default authenticate scheme at the token validation handler removed. Shortening the
access-token lifetime is the cheaper lever, at the price of more refreshes, and refreshes are the
expensive requests.

**Logout without a valid `id_token_hint` is confirmed, not silent.** `/connect/logout` is just a
URL: any site could navigate a signed-in user's browser to it and end their SSO session
everywhere. With a valid hint the relying party has named the session and it is honoured
immediately; without one the user gets a no-JavaScript confirmation page that POSTs back with an
antiforgery token. That form needs an explicit `@Html.AntiForgeryToken()` — the form tag helper
does not inject one when the form carries a literal `action` attribute.

**The `/api` surface requires the `api` scope, through a policy that is actually applied.**
`AccountController`'s three authenticated actions and the whole of `OrganizationController`
carry `[Authorize(Policy = "ApiAccess")]`. They previously named only the authentication
scheme, which asks whether the token is valid and nothing more, so any token from any client
reached the account API and company administration alike — the `ApiAccess` policy was defined
and never used. The policy itself also accepted `offline_access` *or* `api`, because
`RequireClaim` with several values means any of them; `offline_access` is a request for a
refresh token and confers no API authority. A new `[Authorize]` on an `/api` endpoint takes the
policy, not the scheme.

**Clients created through the admin API can revoke their own tokens.** `OidcAppService` grants
`ept:revocation` to every client, public ones included (RFC 7009 §2.1; OpenIddict validates
token presenters, so a client can only revoke what was issued to it). Without it an integrating
app could not revoke the refresh token when it logged a user out, so the token outlived the
logout. Introspection is the other direction — asking about tokens the caller never held — so
it is opt-in per client (`AllowIntrospection`) and refused for public clients, which have no
credentials for an endpoint that authenticates its caller. Note that, like `PkceExempt`, an
update that omits the flag withdraws it.

**Administering the server needs both the `Admin` role and the `admin` scope.** Neither alone: the role without the scope lets any token an administrator holds administer, the scope without the role lets a machine client administer with no human involved.

**Creating a tenancy requires offline signatures.** Mutating tenant endpoints demand an interactive human administrator plus a quorum of detached ECDSA signatures from keys held off the server. It fails closed when no keys are configured. See `docs/TENANT-PROVISIONING.md`.

### OIDC endpoints

All protocol endpoints live under `ConnectController`:

| Endpoint | Purpose |
|---|---|
| `GET /connect/authorize` | Authorization request; redirects to login if unauthenticated |
| `POST /connect/token` | Token exchange (code → access/ID/refresh tokens) |
| `GET /connect/userinfo` | User info (requires valid token) |
| `GET /connect/logout` | Logout |
| `POST /connect/introspect` | Token introspection |
| `POST /connect/revoke` | Token revocation |
| `GET /.well-known/openid-configuration` | Discovery document |
| `GET /.well-known/jwks` | Public key set |

### Secrets

Google and Microsoft OAuth credentials are kept in `dotnet user-secrets` (UserSecretsId: `authserver-api-secrets`), not in `appsettings.json`.

The M2M client secret is **not** in `appsettings.json` either — a secret committed to the repository is a known secret. Supply it per environment and startup fails without it: `dotnet user-secrets set "OpenIddict:M2MClient:ClientSecret" "$(openssl rand -base64 32)"` locally, `M2M_CLIENT_SECRET` in `.env` for the debug stack, generated into `staging/secrets/` by `staging/start.sh`.
