# PixSmith Authorization Server

An OAuth 2.0 / OIDC authorization server built with **.NET 10**, **OpenIddict**, **ASP.NET Identity**, and a **Blazor WASM** admin UI. The Blazor client is hosted by the API — a single process, single port.

---

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- Docker, if you want the containerised setup (Option A below)

---

## First-Time Setup

Two paths. Pick the one matching how you intend to run it.

### Option A — Containers (recommended)

Postgres and the auth server both in Docker. Everything is configured from a single `.env`.

```bash
cp docker/.env.example .env     # then edit the passwords
./debug/start.sh                # or: docker compose up --build
```

`.env` is gitignored. See [docker/README.md](docker/README.md) for the details and
[debug/README.md](debug/README.md) for attaching a debugger.

### Option B — Local, no containers

Non-sensitive settings go in `appsettings.Development.json`; secrets go in `dotnet user-secrets`,
which stores them outside the repository so they cannot be committed by accident.

```bash
cd src/AuthServer/AuthServer.API

# Generated once — this is the client secret machine-to-machine callers present.
dotnet user-secrets set "OpenIddict:M2MClient:ClientSecret" "$(openssl rand -base64 32)"

# The initial admin account, created on first startup (see below).
dotnet user-secrets set "AdminSeed:Email"    "admin@yourcompany.com"
dotnet user-secrets set "AdminSeed:Username" "admin"
dotnet user-secrets set "AdminSeed:Password" "Replace@Me1!"

# Optional — external identity providers.
dotnet user-secrets set "Authentication:Google:ClientId"        "..."
dotnet user-secrets set "Authentication:Google:ClientSecret"    "..."
dotnet user-secrets set "Authentication:Microsoft:ClientId"     "..."
dotnet user-secrets set "Authentication:Microsoft:ClientSecret" "..."

dotnet user-secrets list        # confirm what is set
```

The admin password must satisfy the Identity policy — 8+ characters with an uppercase letter, a
digit, and a special character. A password that does not is not a silent failure: startup throws
with an explicit message naming the policy, because an instance seeded with an unusable admin
would otherwise have no way to log in.

Defaults for everything else live in `appsettings.json` and work as-is for local development
(SQLite at `auth.db`). To point at Postgres instead, override two settings in
`appsettings.Development.json`:

```json
{
  "Database": { "Provider": "Postgres" },
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Port=5432;Database=pixsmith_auth;Username=pixsmith_app;Password=..."
  }
}
```

### Start it

```bash
dotnet run --project src/AuthServer/AuthServer.API
```

On first startup the application:

1. Applies EF Core migrations (creates the database if it does not exist)
2. Seeds the "Admin" and "User" Identity roles
3. Seeds the two default OpenIddict clients (`blazor-client`, `m2m-client`)
4. Creates the initial admin user from the `AdminSeed:*` values — **only when no users exist at
   all**, so these settings can never be used to mint extra accounts on a live system
5. Serves the Blazor WASM admin UI at the same origin

Open the URL printed in the terminal (default `https://localhost:7100`) and sign in.

> Change the admin password after the first login. Once the user exists the seeder is a no-op, so
> the `AdminSeed:*` values are safe to remove.

### Provisioning keys

Creating a tenancy additionally requires a quorum of offline operator signatures, and the server
**refuses to provision until they are configured** — this is deliberate, not a misconfiguration.
Generate the keypairs with `tools/provision-keygen.sh` and enrol the public halves; the full
procedure is in [docs/TENANT-PROVISIONING.md](docs/TENANT-PROVISIONING.md).

### Catching outgoing email in development

Registration confirmation and password-reset emails are sent via SMTP, queued through an outbox and dispatched by a background service (`EmailOutboxDispatcher`) so a slow/unreachable mail server never blocks a request. `appsettings.json` defaults `Email:Smtp` to [Mailpit](https://mailpit.axllent.org/) (`localhost:1025`, no auth) so this works out of the box in dev:

```powershell
docker run -d --name mailpit -p 1025:1025 -p 8025:8025 axllent/mailpit
```

View sent mail at `http://localhost:8025`. For production, override `Email:Smtp:Host/Port/Username/Password` via environment variables or `dotnet user-secrets` — same pattern as the Google/Microsoft OAuth credentials, not `appsettings.json`.

---

## Running in Docker

The project includes a `Dockerfile` (multi-stage, Linux) and a `docker-compose.yml`.

```powershell
# Build and start
docker compose up --build

# Or pull and start a pre-built image
docker compose up
```

The container listens on port **8080** (HTTP). For HTTPS in development, Visual Studio's Docker profile mounts the dev certificate automatically.

### Configuration for containers

Compose reads `.env` from the repository root. Start from the template:

```bash
cp docker/.env.example .env
```

| Variable | Purpose |
|---|---|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` | Postgres superuser — administration only |
| `POSTGRES_DB` | Database name |
| `APP_DB_USER` / `APP_DB_PASSWORD` | Least-privilege role the auth server connects as |
| `AUTH_BASE_URI` | Public URL the OIDC client redirects to |
| `M2M_CLIENT_SECRET` | M2M client secret (rotate before production) |
| `ADMIN_SEED_EMAIL` / `_USERNAME` / `_PASSWORD` | Initial admin, seeded only on an empty database |
| `DOCKER_NETWORK_NAME` / `_EXTERNAL` | Shared network for Postgres and the auth server |
| `POSTGRES_HOST_PORT` | Host port for Postgres (bound to loopback) |

Settings not in that list are overridden with the standard ASP.NET Core double-underscore form,
e.g. `ConnectionStrings__DefaultConnection` or `Authentication__Google__ClientId`.

For a real deployment, inject secrets from your secret store rather than a file on disk.
[docker/README.md](docker/README.md) has the full details.

---

## Configuration Files

| File | Purpose | In source control |
|---|---|---|
| `appsettings.json` | Baseline defaults (non-sensitive) | Yes |
| `appsettings.Development.json` | Local overrides (DB provider, connection string) | Yes |
| `appsettings.Production.json` | Production overrides | Yes |
| `dotnet user-secrets` | Secrets for local, non-container development | No (per-machine) |
| `.env` | Secrets and settings for the container setup | No (gitignored) |
| `docker/.env.example` | Template for `.env`, placeholders only | Yes |

---

## Admin UI

The Blazor WASM client at `/admin` (requires the **Admin** role) provides:

| Page | Route | Description |
|---|---|---|
| Dashboard | `/admin` | User counts, client stats, recent sign-ins |
| Users | `/admin/users` | Paginated list — lock, unlock, activate, deactivate, assign roles |
| Tenants | `/admin/tenants` | Create and manage tenants (name, slug, description, active state) |
| OIDC Apps | `/admin/oidc-apps` | Manage OpenIddict application registrations directly |
| OAuth Clients | `/admin/clients` | Manage the custom OAuth client registry |

---

## OIDC Endpoints

| Endpoint | URL |
|---|---|
| Authorization | `GET  /connect/authorize` |
| Token | `POST /connect/token` |
| UserInfo | `GET  /connect/userinfo` |
| End-session | `GET  /connect/logout` |
| Introspection | `POST /connect/introspect` |
| Revocation | `POST /connect/revoke` |
| JWKS | `GET  /.well-known/jwks` |
| Discovery | `GET  /.well-known/openid-configuration` |

---

## Pre-seeded Clients

| Client ID | Type | Flows | Purpose |
|---|---|---|---|
| `blazor-client` | Public | Authorization Code + PKCE, Password, Refresh Token | Blazor WASM frontend |
| `m2m-client` | Confidential | Client Credentials | Machine-to-machine API access |

To connect an application of your own — registering it, validating its tokens, and driving
permissions from the claims — see **[INTEGRATION.md](INTEGRATION.md)**.

Tenant creation is deliberately not automatable: it requires an interactive human administrator
plus a quorum of offline operator signatures. See
**[docs/TENANT-PROVISIONING.md](docs/TENANT-PROVISIONING.md)**.

---

## Architecture

```
Domain  ←  Application  ←  Infrastructure  ←  API
                                           ←  DataContext  ←  Repositories  ←  Services
```

Dependencies always point inward. The Domain has no external package references.

| Project | Role |
|---|---|
| `AuthServer.Domain` | Aggregates (`ApplicationUser`, `OAuthClient`, `Tenant`), domain events, `Result<T>` |
| `AuthServer.Infrastructure` | EF Core + OpenIddict + Identity wiring, `OpenIddictSeeder` |
| `PixSmith.Authorization.DataContext` | `ApplicationDbContext`, EF records, shared DTOs |
| `PixSmith.Authorization.Repositories` | EF Core repository implementations |
| `PixSmith.Authorization.Services` | Business logic (`UserService`, `OAuthClientService`, `TenantService`, `OidcAppService`) |
| `AuthServer.API` | Controllers, `Program.cs`, `AdminUserSeeder` |
| `BlazorClient` | Blazor WASM SPA — hosted by the API at the same origin |

---

## Production Checklist

- [ ] Change the M2M client secret (`OpenIddict__M2MClient__ClientSecret`)
- [ ] Remove `AdminSeed__*` environment variables after first boot
- [ ] Replace SQLite with PostgreSQL or SQL Server
- [ ] Replace `AddEphemeralEncryptionKey/SigningKey` with real X.509 certificates
- [ ] Mount a persistent volume for `/app/data` (database + data-protection keys)
- [ ] Set `RequireConfirmedEmail = true` and implement `IEmailService`
- [ ] Configure a reverse proxy (nginx, Traefik) and set `OpenIddict__BlazorClient__BaseUri` to the public URL
- [ ] Review Identity password and lockout policy in `appsettings.json`

---

## Development Commands

```powershell
# Restore and build
dotnet restore
dotnet build OAuthSolution.sln

# Run (serves API + Blazor WASM at https://localhost:7100)
dotnet run --project src/AuthServer/AuthServer.API

# Add an EF Core migration.
# Migrations live in the provider-specific projects, not in DataContext, and each
# provider needs its own — run this twice, once per provider.
dotnet ef migrations add <MigrationName> `
  --project src/PixSmith.Authorization.DataContext.Migrations.Sqlite `
  --startup-project src/AuthServer/AuthServer.API

dotnet ef migrations add <MigrationName> `
  --project src/PixSmith.Authorization.DataContext.Migrations.Postgres `
  --startup-project src/AuthServer/AuthServer.API

# Apply migrations manually (also runs automatically on startup)
dotnet ef database update `
  --project src/PixSmith.Authorization.DataContext.Migrations.Sqlite `
  --startup-project src/AuthServer/AuthServer.API

# View configured user-secrets
dotnet user-secrets list --project src/AuthServer/AuthServer.API
```
