# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build & restore
dotnet restore
dotnet build OAuthSolution.sln

# Run the auth server (https://localhost:7100)
cd src/AuthServer/AuthServer.API && dotnet run

# Run the Blazor WASM client (https://localhost:7200)
cd src/BlazorClient && dotnet run
```

No test projects exist yet. No lint tooling is configured beyond `<Nullable>enable</Nullable>` and `<ImplicitUsings>enable</ImplicitUsings>` in all projects.

## Architecture

This is an OAuth 2.0 / OIDC authorization server built with **OpenIddict** on **ASP.NET Core + Identity**. It follows Onion Architecture; dependency flow is strictly inward:

```
Domain ← Application ← Infrastructure ← API
                                      ← DataContext ← Repositories ← Services
```

The `src/AuthServer/` folder contains the server-side projects. `src/BlazorClient/` is a Blazor WASM SPA that acts as an OIDC client consuming the auth server.

### Project roles

| Project | Role |
|---|---|
| `PixSmith.Authorization.Domain` | Pure aggregates (`ApplicationUser`, `OAuthClient`), domain events, and `Result<T>` monad — zero external dependencies |
| `AuthServer.Application` | Use-case DTOs, `IUserService` / `IOAuthClientService` interfaces, FluentValidation validators |
| `AuthServer.Infrastructure` | EF Core + OpenIddict + ASP.NET Identity wiring; `OpenIddictSeeder` hosted service seeds default clients on startup |
| `PixSmith.Authorization.API` | HTTP entry point — `ConnectController` (OIDC protocol), `AccountController` (login/SSO), `AdminController` (user & client management) |
| `PixSmith.Authorization.DataContext` | `ApplicationDbContext` combining Identity + OpenIddict + custom tables (`UserProfile`, `OAuthClientRegistration`, `AuditLog`) |
| `PixSmith.Authorization.Repositories` | EF Core implementations of `IUserRepository` / `IOAuthClientRepository` |
| `PixSmith.Authorization.Services` | `UserService`, `OAuthClientService`, `PasswordHashingService`, `EmailService` (stub) |
| `BlazorClient` | Blazor WASM SPA; uses Authorization Code + PKCE via `AddOidcAuthentication()` |

### Key design points

**Two parallel user models.** `ApplicationUser` (Domain) is a framework-free aggregate that tracks login attempts, lockout, roles, external logins, and 2FA state entirely in domain logic. `IdentityUser<Guid>` (ASP.NET Identity) handles the actual persistence and password hashing. They are kept in sync by `UserService`.

**OpenIddict over IdentityServer.** OpenIddict runs in-process, shares the EF Core `DbContext`, and integrates directly with ASP.NET Identity — no separate server process needed.

**PKCE required for public clients.** The Blazor client (`blazor-client`) is a pre-seeded public client. The M2M client (`m2m-client`) is confidential and uses Client Credentials.

**Error handling via Result<T>.** Domain methods return `Result<T>` instead of throwing exceptions. Infrastructure and service layers map these to HTTP responses in controllers.

**Database auto-migrates on startup.** `EnsureCreatedAsync()` is called in `Program.cs` — development uses SQLite (`auth.db`). For production, swap the connection string to PostgreSQL or SQL Server.

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
