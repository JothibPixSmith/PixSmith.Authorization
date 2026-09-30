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
| `BlazorClient` | Blazor WASM admin UI, served by the API at the same origin. Signs in with the **password grant** via `JwtAuthStateProvider` (not `AddOidcAuthentication`), stores tokens in `localStorage`, and reads claims from `/api/account/me` rather than parsing the token |

### Key design points

**Two parallel user models.** `ApplicationUser` (Domain) is a framework-free aggregate that tracks login attempts, lockout, roles, external logins, and 2FA state entirely in domain logic. `IdentityUser<Guid>` (ASP.NET Identity) handles the actual persistence and password hashing. They are kept in sync by `UserService`.

**OpenIddict over IdentityServer.** OpenIddict runs in-process, shares the EF Core `DbContext`, and integrates directly with ASP.NET Identity — no separate server process needed.

**PKCE required for public clients.** The Blazor client (`blazor-client`) is a pre-seeded public client. The M2M client (`m2m-client`) is confidential and uses Client Credentials.

**Error handling via Result<T>.** Domain methods return `Result<T>` instead of throwing exceptions. Infrastructure and service layers map these to HTTP responses in controllers.

**Database migrates on startup.** `Program.cs` calls `db.Database.MigrateAsync()` before the host starts. `Database:Provider` selects SQLite (default, `auth.db`) or Postgres; migrations live in two provider-specific projects and **both must be generated** for any model change, or the other provider fails at runtime.

**Tenancy is enforced.** A user reaches an application when they are an active member of an active company that subscribes to that client — checked at `/connect/authorize`, on the password grant, and on every refresh. Tokens carry `org_id`, `org_slug` and a plural `roles` claim (company roles); the singular `role` claim carries platform Identity roles and is separate. `TenantEnforcement:PlatformClients` exempts clients that administer the server itself. See `docs/MULTI-TENANCY.md`.

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

Google and Microsoft OAuth credentials are kept in `dotnet user-secrets` (UserSecretsId: `authserver-api-secrets`), not in `appsettings.json`. The seeded M2M client secret (`"m2m-super-secret-change-in-production"`) must be rotated before any production deployment.
