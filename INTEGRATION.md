# Integrating Another Application

How to put a second application behind this auth server: register it, validate its tokens, and drive permissions from the claims it receives.

This guide is written for a **backend API (resource server)** — an app that receives access tokens and enforces permissions — plus the sign-in flow used by whatever client fronts it.

---

## The model

Three roles, and it is worth keeping them straight:

| Role | Who | Responsibility |
|---|---|---|
| **Authorization server** | this app | Owns identity. Authenticates the human, issues tokens. |
| **Client** | the thing the user touches (SPA, web app, mobile) | Starts the sign-in redirect, holds the tokens, calls the API. |
| **Resource server** | your other app's API | Receives the token, validates it, enforces permissions. |

The auth server answers *who is this*. Your app answers *what may they do here*. Don't move either question across the line.

---

## Why the login page lives on the auth server

**The auth server hosts the login page. Your app redirects to it.** Your app may still have its own branded landing page — it just needs a button that redirects, not a form that collects a password.

1. **SSO only exists if there is one session.** The session is a cookie on the auth server's domain. A login form in your app means a second, independent session — users sign in twice and signing out of one leaves the other live.
2. **Your app never touches credentials.** It only ever sees an authorization code and tokens. A compromise of your app cannot leak passwords.
3. **MFA, lockout, email confirmation, password reset, and the Google/Microsoft external logins live in one place.** A login form per app either re-implements all of it or quietly loses it.
4. **The only way to have a local login form is the password grant (ROPC)** — removed in OAuth 2.1, incompatible with external identity providers, MFA, and consent. The Blazor admin UI in this repo uses ROPC for its own first-party login; do not copy that pattern into a new app.

---

## Step 1 — Register a scope for your app

A scope is what a client is allowed to *ask for*, and it determines the `aud` (audience) claim your API validates.

Scopes are seeded in code, not through the admin UI. Two edits:

**`src/AuthServer/AuthServer.API/InfrastructureServiceExtensions.cs`** — add it to the registered scope list:

```csharp
options.RegisterScopes(
    Scopes.Email, Scopes.Profile, Scopes.Roles,
    Scopes.OpenId, Scopes.OfflineAccess, "api", "admin",
    "myapp.api");                                        // ← new
```

**`src/AuthServer/AuthServer.Infrastructure/OpenIddict/OpenIddictSeeder.cs`** — seed it, with its own resource name:

```csharp
await EnsureScopeAsync(scopeManager, "myapp.api", "My App API", cancellationToken);
```

> **Scopes are managed at runtime, not seeded in code.** Create one per application through the
admin API — a scope's `resources` become the `aud` of every token granted it, which is what
makes audience validation mean something:

```bash
curl -X POST https://localhost:7100/api/admin/oidc-scopes \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"myapp.api","displayName":"My App API","resources":["myapp-api"]}'
```

Then grant `myapp.api` to your client. Your resource server validates
`AddAudiences("myapp-api")`, and a token minted for another application is no longer
audience-valid at yours.

The built-in `api` and `admin` scopes both map to the shared `resource-server` audience and are
read-only — changing them would alter the `aud` of tokens that deployed integrations already
validate. Use a per-application scope instead.

**Migrating an existing integration without downtime.** A token carries one audience per
granted scope, so both can be live at once:

1. Create `myapp.api` and grant it to the client *alongside* the existing `api`. Tokens now
   carry `aud: ["resource-server", "myapp-api"]` — old validation still passes, nothing breaks.
2. Switch the resource server to `AddAudiences("myapp-api")`. Still passing, because the token
   carries both.
3. Remove `api` from the client. `aud` becomes `["myapp-api"]` alone.

Step 3 is the one that delivers the isolation — it is easy to stop after step 2 and believe
you are done.

---

## Step 2 — Register the client

This part needs no code. Use the admin UI (**Admin → OIDC Apps**) or the API:

```bash
curl -X POST https://localhost:7100/api/admin/oidc-apps \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "myapp-web",
    "clientSecret": null,
    "displayName": "My App",
    "clientType": "public",
    "redirectUris": ["https://myapp.local/signin-oidc"],
    "postLogoutRedirectUris": ["https://myapp.local/signout-callback-oidc"],
    "scopes": ["openid", "profile", "email", "roles", "offline_access", "myapp.api"],
    "grantTypes": ["authorization_code", "refresh_token"]
  }'
```

Pick the client type by where the code runs:

| Your client | `clientType` | `grantTypes` | Secret |
|---|---|---|---|
| Server-rendered web app (MVC / Razor / Blazor Server) | `confidential` | `authorization_code`, `refresh_token` | Yes |
| SPA (Blazor WASM, React, …) | `public` | `authorization_code`, `refresh_token` | No — PKCE instead |
| Mobile / desktop native | `public` | `authorization_code`, `refresh_token` | No — PKCE instead |
| Backend service, no user | `confidential` | `client_credentials` | Yes |

PKCE is enforced automatically for public clients using the authorization code flow, and `RequireProofKeyForCodeExchange()` is set server-wide.

Redirect URIs are matched exactly, including scheme, port, and trailing slash.

### Register one client per deployment, not one per application

`myapp-web` is not an application — it is *one deployment of* an application. Register
production, staging and local separately:

```
myapp-web-prod        redirect: https://myapp.com/signin-oidc
myapp-web-staging     redirect: https://staging.myapp.com/signin-oidc
myapp-web-local       redirect: https://localhost:5001/signin-oidc
```

The reason is that **a client secret is the client's identity, not a per-instance credential.**
Every deployment sharing `client_id` presents identical credentials, and the server has no way
to tell them apart — that is the design, not a gap. Two consequences follow, and both are
avoided by separate registrations:

- **A leaked staging secret mints production tokens.** Same client, same authority.
- **Rotating the secret breaks every deployment at once.** OpenIddict stores a single
  `ClientSecret` per application — there is no list and no overlap window, so the usual
  "add the new secret, roll out, remove the old" sequence is not available. Rotation is
  necessarily a hard cutover.

Separate registrations shrink the blast radius of both to one environment. It costs nothing
but a few extra rows, and it is far cheaper to do now than to untangle after a leak.

Keep the `clientId` values distinct but the *scopes* identical, so a token minted in staging
still fails against production by audience rather than by permissions.

### For anything genuinely sensitive, skip shared secrets entirely

A shared secret has to exist in a config file, an environment variable, or a deployment
pipeline somewhere. The alternative is **client assertions** (`private_key_jwt`): each
deployment holds its own private key, signs a short-lived assertion, and the server stores
only public keys.

OpenIddict supports this — the application descriptor carries a `JsonWebKeySet`, and its
own validation message offers it as the alternative to a secret:

> …alternatively, a RSA or ECDSA key (with the key use "sig") can be added to the JSON Web
> Key Set attached to the application if the client authenticates using client assertions.

That gives what a shared secret structurally cannot:

| | Shared secret | Client assertion |
|---|---|---|
| Credential per deployment | No — one value, copied everywhere | Yes — each holds its own key |
| Zero-downtime rotation | No — single stored value, hard cutover | Yes — a JWKS holds several keys at once |
| Secret at rest on the server | Hashed, but present | Public keys only |

Register a client with a key set instead of a secret by passing `jsonWebKeySet` (raw JWKS
JSON) and leaving `clientSecret` null:

```bash
curl -X POST https://localhost:7100/api/admin/oidc-apps \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "clientId": "myapp-service-prod",
    "clientSecret": null,
    "clientType": "confidential",
    "grantTypes": ["client_credentials"],
    "scopes": ["myapp.api"],
    "redirectUris": [], "postLogoutRedirectUris": [],
    "jsonWebKeySet": "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"2026-09\",\"use\":\"sig\",\"alg\":\"ES256\",\"x\":\"…\",\"y\":\"…\"}]}"
  }'
```

`GET /api/admin/oidc-apps` returns the registered keys' `kid`, `kty`, `alg` and `use` under
`signingKeys`, so you can confirm which key a deployment is on. On update, `jsonWebKeySet`
omitted keeps the registered set; supplied replaces it wholesale — which is how you roll a
key: publish both, move the deployments, then re-register with only the new one.

**Private key material is refused, not stripped.** A key carrying `d`, `p`, `q`, `dp`, `dq`,
`qi` or `k` is rejected with an explicit message telling you to treat that key as compromised.
Silently stripping it would accept a request in which someone has just pasted their private
key into an HTTP body and say nothing.

### Two things that will bite when you write the client

Both cost real time to diagnose from the error text alone:

**The assertion needs `"typ": "client-authentication+jwt"`.** A plain `"typ": "JWT"` is
rejected with *"The specified token is not of the expected type"* (ID2089). OpenIddict
enforces the RFC 7523bis media type so a token minted for one purpose cannot be replayed as a
client credential. In .NET, set `SecurityTokenDescriptor.TokenType`.

**The `kid` must match and the key must genuinely be the public half of your signing key.**
A mismatch reports *"The signing key associated to the specified token was not found"*
(ID2090) — the same error you get for a wrong `kid`, a wrong curve, or a public key that
simply is not the pair of the private one. Derive the JWKS from the private key
programmatically rather than transcribing it.

Then authenticate with no secret at all:

```bash
curl -X POST https://localhost:7100/connect/token \
  -d grant_type=client_credentials \
  -d client_id=myapp-service-prod \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$SIGNED_JWT" \
  -d scope=myapp.api
```

---

## Step 3 — Validate tokens in your API

Access tokens are signed RS256 JWTs. Your API validates them against the auth server's published key set at `/.well-known/jwks` — no shared secret, no database access, no call back to the auth server per request.

```xml
<PackageReference Include="OpenIddict.Validation.AspNetCore" Version="7.*" />
<PackageReference Include="OpenIddict.Validation.SystemNetHttp" Version="7.*" />
```

```csharp
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

builder.Services.AddOpenIddict()
    .AddValidation(options =>
    {
        options.SetIssuer("https://localhost:7100/");   // trailing slash matters
        options.AddAudiences("resource-server");        // must match the scope's resource
        options.UseSystemNetHttp();
        options.UseAspNetCore();
    });

builder.Services.AddAuthentication(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
```

In development, the auth server uses a self-signed certificate. Add this **inside the `AddValidation` block, guarded by environment** so discovery doesn't fail:

```csharp
if (builder.Environment.IsDevelopment())
{
    options.UseSystemNetHttp()
           .ConfigureHttpClientHandler(h =>
               h.ServerCertificateCustomValidationCallback = (_, _, _, _) => true);
}
```

**Non-.NET apps** use any standard OIDC library pointed at `https://localhost:7100/.well-known/openid-configuration` — the discovery document advertises the JWKS URI, and signature validation works the same way.

---

## Step 4 — Enforce permissions

The token carries two useful things:

- **`scope`** — what the *client application* was granted. Coarse. Use it as a gate on whole APIs.
- **`role`** — who the *user* is. These are the Identity roles from the auth server (`Admin`, `User`, plus anything you add).

```csharp
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ApiAccess", p =>
    {
        p.RequireAuthenticatedUser();
        p.RequireClaim(Claims.Private.Scope, "myapp.api");
    });

    options.AddPolicy("AdminOnly", p =>
    {
        p.RequireAuthenticatedUser();
        p.RequireAssertion(ctx => ctx.User.HasClaim(Claims.Role, "Admin"));
    });
});

app.MapGet("/orders", …).RequireAuthorization("ApiAccess");
```

> Use `HasClaim(Claims.Role, …)` rather than `User.IsInRole(…)`. The principal rebuilt by OpenIddict validation uses the default Windows-URI role claim type, which does not match the JWT's short-form `role` claim. `AdminController` in this repo hits the same issue and solves it the same way.

### Fine-grained permissions belong in your app

The roles here are **global** — an `Admin` on the auth server is an `Admin` everywhere. That's the right granularity for "who is this person"; it is the wrong granularity for "may they delete an invoice in this app".

The clean split is a local permission table in your app keyed on the `sub` claim (a stable GUID that never changes for a user):

```csharp
var userId = Guid.Parse(User.FindFirst(Claims.Subject)!.Value);
var perms  = await db.AppPermissions.Where(p => p.UserId == userId).ToListAsync();
```

Your app owns that table, adds and revokes rows, and never has to ask the auth server for permission changes. The auth server stays a pure identity provider.

> **Multi-tenancy:** the `Tenant` and `UserRole` entities exist in the domain but `ConnectService.BuildIdentityAsync` does not emit a tenant claim. If your app is tenant-scoped, add the claim there and give it an `AccessToken` destination in `GetDestinations`.

> **Tenancies cannot be created by your application.** Provisioning a tenancy requires an
> interactive human administrator plus a quorum of offline operator signatures — a
> client-credentials token is refused outright, whatever scopes it holds. If your integration
> assumed it could self-register a tenancy, it cannot; that step is deliberately manual. See
> **[docs/TENANT-PROVISIONING.md](docs/TENANT-PROVISIONING.md)**.

---

## Step 5 — Sign the user in

Full authorization code + PKCE flow, exactly as verified against this server:

```
Browser                    Your app                  Auth server
   │                          │                           │
   │──── GET /orders ────────►│                           │
   │◄─── 302 to authorize ────│                           │
   │────────── GET /connect/authorize ──────────────────► │
   │◄───────── 302 /Account/Login?ReturnUrl=… ─────────── │  no session
   │────────── POST /Account/Login ───────────────────►   │
   │◄───────── 302 + Identity cookie ──────────────────── │  ← SSO session
   │────────── GET /connect/authorize ─────────────────►  │
   │◄───────── 302 …/signin-oidc?code=… ──────────────── │
   │──── GET /signin-oidc ───►│                           │
   │                          │── POST /connect/token ──► │
   │                          │◄─ access + id + refresh ─ │
   │◄─── 302 + app cookie ────│                           │
```

The second time a user arrives — from this app or any other — the Identity cookie already exists, so `/connect/authorize` returns a code without showing the login page. That is the SSO payoff, and it only works because the login page lives on the auth server.

For a server-rendered .NET client:

```csharp
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme          = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie()
.AddOpenIdConnect(options =>
{
    options.Authority    = "https://localhost:7100/";
    options.ClientId     = "myapp-web";
    options.ClientSecret = builder.Configuration["Oidc:ClientSecret"];
    options.ResponseType = "code";
    options.UsePkce      = true;
    options.SaveTokens   = true;

    options.Scope.Clear();
    foreach (var s in new[] { "openid", "profile", "email", "roles", "offline_access", "myapp.api" })
        options.Scope.Add(s);

    options.TokenValidationParameters.RoleClaimType = "role";
    options.TokenValidationParameters.NameClaimType = "name";
});
```

`SaveTokens = true` puts the access token in the auth cookie; retrieve it with `await HttpContext.GetTokenAsync("access_token")` to call your API.

### Machine-to-machine

No user, no redirect — just a client secret:

```bash
curl -X POST https://localhost:7100/connect/token \
  -d grant_type=client_credentials \
  -d client_id=myapp-service \
  -d client_secret=… \
  -d scope=myapp.api
```

The resulting token has `sub` = the client ID and **no role claims**, so any role-based policy correctly rejects it. Gate service endpoints on scope, not role.

---

## Verify it end to end

With the server running on `https://localhost:7100`:

```bash
# 1. Discovery
curl -k https://localhost:7100/.well-known/openid-configuration | jq .

# 2. Machine token
curl -k -X POST https://localhost:7100/connect/token \
  -d grant_type=client_credentials -d client_id=m2m-client \
  -d client_secret=… -d scope=api

# 3. Decode it — should be 3 segments (signed JWT), not 5 (encrypted JWE)
#    and carry iss / aud / sub / scope
```

For the interactive flow, open `/connect/authorize?client_id=…&response_type=code&redirect_uri=…&scope=openid%20profile%20email%20roles&code_challenge=…&code_challenge_method=S256&state=…` in a browser. You should land on the auth server's login page and return to your redirect URI with a `code`.

---

## What was changed in this repo to make this work

Three things had to be fixed before an external app could integrate at all:

**1. A server-rendered login page now exists.** `/connect/authorize` challenges the Identity application cookie, but nothing in this app ever issued that cookie — the Blazor admin UI signs in over the password grant, which validates credentials without creating a session. The challenge redirected to Identity's default `/Account/Login`, which didn't exist, fell through to the Blazor SPA, and looped forever. Added:

- [LoginController.cs](src/AuthServer/AuthServer.API/Controllers/LoginController.cs) — `GET`/`POST /Account/Login`, calls `PasswordSignInAsync`, honors `ReturnUrl` (validated with `Url.IsLocalUrl` against open redirects), handles lockout / unconfirmed email / 2FA-required
- [Views/Login/Index.cshtml](src/AuthServer/AuthServer.API/Views/Login/Index.cshtml) — the form, styled to match the Blazor UI
- `ConfigureApplicationCookie` in [InfrastructureServiceExtensions.cs](src/AuthServer/AuthServer.API/InfrastructureServiceExtensions.cs) — sets `LoginPath`, 8-hour sliding expiry, `SameSite=Lax` (required: the browser reaches `/connect/authorize` as a cross-site redirect and `Strict` would suppress the cookie, silently breaking SSO)
- `AddControllers()` → `AddControllersWithViews()` in [Program.cs](src/AuthServer/AuthServer.API/Program.cs)

**2. Access tokens are no longer encrypted.** `DisableAccessTokenEncryption()` was added to the OpenIddict server options. OpenIddict encrypts access tokens by default, producing a 5-segment JWE that an external resource server cannot read — validation is only possible in-process. Tokens are still signed and still verified against JWKS; authorization codes and refresh tokens remain encrypted. The Blazor admin UI is unaffected: it never parsed the token, it reads claims from `/api/account/me`.

**3. Nothing else.** Client registration already worked through the admin API.

---

## Before production

- **Replace the ephemeral signing keys.** `AddEphemeralSigningKey()` / `AddEphemeralEncryptionKey()` generate a new key on every start, so every restart invalidates every token in every app and rotates the JWKS out from under your resource servers. Load real X.509 certificates from a secret store.
- **Rotate the seeded M2M secret** (`m2m-super-secret-change-in-production`) via
  `POST /api/admin/oidc-apps/{clientId}/rotate-secret`, or **Rotate secret** on the
  Admin → OIDC Apps page. The response carries the new value once and it is stored hashed
  thereafter, so copy it immediately. Rotation is deliberately a separate endpoint from
  updating an application, so editing a redirect URI cannot invalidate a live client's
  credentials by accident.
- **Register one client per deployment**, not one per application — see
  [Step 2](#register-one-client-per-deployment-not-one-per-application). Rotation is a hard
  cutover with no overlap window, so this is what stops it taking every environment down at
  once, and what keeps a leaked staging secret from minting production tokens.
- **Give each app its own scope resource** so audiences actually isolate apps — see the caveat in Step 1.
- **Add CORS** if any client is browser-based on a different origin. No CORS middleware is currently registered.
- **Add a consent screen** if you ever onboard a third-party app. `ConnectController.Authorize` auto-approves every request, which is correct for first-party apps you own and wrong for anyone else's.
- **Persist data protection keys** (`DataProtection:KeyPath`) if you run more than one instance.
