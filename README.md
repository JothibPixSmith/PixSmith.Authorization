# 🔐 AuthServer — OAuth 2.0 / OIDC Platform

A **production-grade** Authorization Server built with **.NET 10**, **Blazor WASM**, and **OpenIddict**, following **Onion Architecture** principles.

---

## 📐 Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        Blazor WASM Client                   │
│  (SPA — public OIDC client, PKCE, SSO buttons, Admin UI)   │
└───────────────────────┬─────────────────────────────────────┘
                        │ HTTPS / OIDC
┌───────────────────────▼─────────────────────────────────────┐
│                     AuthServer.API                          │
│  Controllers: /connect/*, /api/account, /api/admin          │
│  • OpenIddict protocol endpoints                            │
│  • External SSO (Google, Microsoft)                         │
│  • ASP.NET Identity sign-in                                 │
└───────────────────────┬─────────────────────────────────────┘
                        │ (depends on)
┌───────────────────────▼─────────────────────────────────────┐
│                  AuthServer.Application                     │
│  • IUserService / IOAuthClientService                       │
│  • DTOs, Result<T> monad                                    │
│  • Business logic (pure, framework-free)                    │
└───────────────────────┬─────────────────────────────────────┘
           ┌────────────┤ (depends on)
           │            │
┌──────────▼──────┐  ┌──▼──────────────────────────────────┐
│ AuthServer      │  │      AuthServer.Infrastructure       │
│ .Domain         │  │  • EF Core + SQLite (swap-able)      │
│                 │  │  • OpenIddict EF Core store          │
│ • Entities      │  │  • ASP.NET Identity integration      │
│ • Value Objects │  │  • IPasswordHasher impl              │
│ • Interfaces    │  │  • OpenIddictSeeder (hosted service) │
│ • Domain Events │  │  • External SSO provider setup       │
│ • Enums         │  └──────────────────────────────────────┘
│                 │
│ ⚠️ NO external  │
│ dependencies    │
└─────────────────┘
```

### Onion Architecture Dependency Rule
> Dependencies always point **inward**. Domain knows nothing about Infrastructure.

| Layer | Depends On | NuGet Packages |
|---|---|---|
| **Domain** | *(nothing)* | None |
| **Application** | Domain | FluentValidation |
| **Infrastructure** | Domain + Application | EF Core, OpenIddict, Identity |
| **API** | Application + Infrastructure | ASP.NET Core, Swagger, Serilog |
| **Blazor Client** | *(standalone)* | WebAssembly.Authentication |

---

## 🚀 Getting Started

### Prerequisites
- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- An IDE (Visual Studio 2022+, Rider, or VS Code)

### 1. Clone & Build

```bash
git clone <repo-url>
cd OAuthSolution
dotnet restore
dotnet build
```

### 2. Configure Secrets (development)

```bash
cd src/AuthServer/AuthServer.API

# Store provider secrets (never commit these!)
dotnet user-secrets set "Authentication:Google:ClientId" "YOUR_GOOGLE_CLIENT_ID"
dotnet user-secrets set "Authentication:Google:ClientSecret" "YOUR_GOOGLE_CLIENT_SECRET"
dotnet user-secrets set "Authentication:Microsoft:ClientId" "YOUR_MS_CLIENT_ID"
dotnet user-secrets set "Authentication:Microsoft:ClientSecret" "YOUR_MS_CLIENT_SECRET"
```

### 3. Run the Auth Server

```bash
cd src/AuthServer/AuthServer.API
dotnet run
# Listening on https://localhost:7100
# Swagger UI: https://localhost:7100/swagger
```

### 4. Run the Blazor Client

```bash
cd src/BlazorClient
dotnet run
# Listening on https://localhost:7200
```

### 5. Create Your First Admin User

After starting the API, use the Swagger UI or curl:

```bash
# Register
curl -X POST https://localhost:7100/api/account/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@example.com","password":"Admin@1234","confirmPassword":"Admin@1234","firstName":"Admin","lastName":"User"}'

# Promote to Admin (requires being authenticated as Admin first — seed one via DB or API)
curl -X POST https://localhost:7100/api/admin/users/{USER_ID}/roles \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"roleName":"Admin"}'
```

---

## 🔑 OAuth 2.0 Flows Supported

| Flow | Use Case | Pre-seeded Client |
|---|---|---|
| **Authorization Code + PKCE** | Blazor WASM, SPAs, Mobile | `blazor-client` (public) |
| **Client Credentials** | Machine-to-Machine (M2M) | `m2m-client` (confidential) |
| **Refresh Token** | Long-lived sessions | Included in above |

### Well-Known Endpoints

| Endpoint | URL |
|---|---|
| Authorization | `GET  /connect/authorize` |
| Token | `POST /connect/token` |
| UserInfo | `GET  /connect/userinfo` |
| Logout | `GET  /connect/logout` |
| JWKS | `GET  /.well-known/jwks` |
| Discovery | `GET  /.well-known/openid-configuration` |

---

## 🔒 SSO Providers

The API supports three external providers out of the box:

| Provider | Login URL | Callback |
|---|---|---|
| Google | `/api/account/external-login?provider=Google` | `/signin-google` |
| Microsoft | `/api/account/external-login?provider=Microsoft` | `/signin-microsoft` |

**How SSO works in this app:**
1. User clicks "Sign in with Google" in the Blazor UI
2. Redirected to `/api/account/external-login?provider=Google`
3. API redirects to Google OAuth
4. Google redirects back to `/api/account/external-login-callback`
5. `UserService.FindOrCreateFromExternalLoginAsync` finds or creates a domain user
6. ASP.NET Identity links the external login
7. User is signed in and redirected to the return URL

---

## 🛡️ Admin Dashboard

The Blazor client has a full admin section at `/admin` (requires `Admin` role):

- **Dashboard** — user counts, client counts, recent sign-ins
- **User Management** — paginated table, lock/unlock, activate/deactivate, assign roles
- **OAuth Client Management** — create/view/delete OIDC clients with live secret reveal

---

## 📁 Project Structure

```
OAuthSolution/
├── OAuthSolution.sln
└── src/
    ├── AuthServer/
    │   ├── AuthServer.Domain/               # Pure domain — no deps
    │   │   ├── Entities/
    │   │   │   ├── ApplicationUser.cs       # Core user aggregate
    │   │   │   ├── OAuthClient.cs           # Client aggregate
    │   │   │   └── UserRole.cs              # Value objects
    │   │   ├── Enums/Enums.cs
    │   │   ├── Events/DomainEvents.cs       # Domain event records
    │   │   └── Interfaces/
    │   │       ├── IRepositories.cs         # Repository + UoW contracts
    │   │       └── IServices.cs             # Service contracts
    │   │
    │   ├── AuthServer.Application/          # Use cases
    │   │   ├── DTOs/Dtos.cs                 # Request/Response models + Result<T>
    │   │   └── Services/
    │   │       ├── UserService.cs           # User use cases
    │   │       └── OAuthClientService.cs    # Client CRUD use cases
    │   │
    │   ├── AuthServer.Infrastructure/       # Framework implementations
    │   │   ├── Data/ApplicationDbContext.cs # EF Core context + Identity + OpenIddict
    │   │   ├── OpenIddict/OpenIddictSeeder.cs # Seeds dev clients on startup
    │   │   ├── Services/IdentityPasswordHasher.cs
    │   │   └── InfrastructureServiceExtensions.cs # DI registration
    │   │
    │   └── AuthServer.API/                  # HTTP layer
    │       ├── Controllers/
    │       │   ├── ConnectController.cs     # OIDC protocol endpoints
    │       │   ├── AccountController.cs     # Auth + SSO callbacks
    │       │   └── AdminController.cs       # Admin API
    │       ├── appsettings.json
    │       └── Program.cs                   # Composition root
    │
    └── BlazorClient/                        # Blazor WASM frontend
        ├── Pages/
        │   ├── Index.razor                  # Home / landing
        │   ├── Profile.razor                # User profile
        │   ├── Auth/Authentication.razor    # OIDC callbacks
        │   └── Admin/
        │       ├── Dashboard.razor          # Stats overview
        │       ├── Users.razor              # User management
        │       └── Clients.razor            # OAuth client management
        ├── Services/ApiServices.cs          # Typed HTTP clients
        ├── Shared/                          # Layout + UI components
        ├── wwwroot/
        │   ├── index.html                   # SPA host page
        │   └── appsettings.json             # OIDC config (authority, clientId)
        ├── _Imports.razor
        ├── App.razor                        # Router + auth state
        └── Program.cs                       # OIDC + HTTP client setup
```

---

## 🏭 Moving to Production

### 1. Database
Replace SQLite with PostgreSQL or SQL Server:

```csharp
// In InfrastructureServiceExtensions.cs, swap:
options.UseSqlite(connectionString);
// For:
options.UseNpgsql(connectionString);       // PostgreSQL
options.UseSqlServer(connectionString);    // SQL Server
```

### 2. Signing Certificates
Replace development certificates with real ones:

```csharp
// In InfrastructureServiceExtensions.cs, swap:
options.AddDevelopmentEncryptionCertificate()
       .AddDevelopmentSigningCertificate();
// For:
options.AddEncryptionCertificate(cert)
       .AddSigningCertificate(cert);
```

### 3. Token Lifetimes
Tune token lifetimes in `appsettings.json` and the OpenIddict client descriptor.

### 4. Email Confirmation
Set `options.SignIn.RequireConfirmedEmail = true` and implement `IEmailService` (SMTP/SendGrid/etc.)

### 5. HTTPS / Reverse Proxy
Ensure `UseForwardedHeaders()` is called if running behind nginx/YARP.

---

## 🧩 Key Design Decisions

| Decision | Choice | Why |
|---|---|---|
| Auth server framework | **OpenIddict** | Fully integrated with EF Core + Identity; no separate server process needed |
| Architecture | **Onion / Clean** | Domain stays framework-free; easy to test and evolve |
| ORM | **EF Core** | Matches Identity and OpenIddict EF Core stores |
| Frontend auth | **MSAL-style OIDC** via `WebAssembly.Authentication` | Built-in PKCE, token storage, silent refresh |
| Styling | **Tailwind CSS** (CDN) | No build step required for Blazor WASM |
| Logging | **Serilog** | Structured logging, easy sink swapping |

---

## 📜 License
MIT
