# Multi-Tenancy Design

**Status: design, not built.** Nothing in this document is implemented yet. The `Tenants` table
exists but is inert — no foreign key points at it and no issued token mentions it.

This describes how to introduce three tiers of user — platform, company, application — using a
single identity, without inventing anything OAuth 2.0 and OpenID Connect do not already support.

---

## The principle

**Three kinds of user are three relationships, not three user tables.**

One person, one row in `Users`, one `sub` value, forever. "Platform staff", "member of Acme Corp",
and "user of the Invoicing app" are all statements *about* that person, not different species of
person. Splitting the identity store is the decision that later makes SSO, account linking, and
"this contractor works for two of our customers" unfixable.

## Nested, not orthogonal

Application access is **inherited through the company**:

```
Tenant (company)
  ├── subscribes to → Application (OIDC client)
  └── has members  → User
                       └── may use an app  ⟺  their company subscribes to it
```

A user's access to an application is derived, not granted directly. Onboarding someone to a
company grants them that company's applications; cancelling a company's subscription removes it
for every member at once. Per-member restriction within the company is possible as an override,
but the default is inheritance.

---

## What the standards actually give us

OAuth 2.0 has no user model, no tenant, and no notion of "kinds of user" — it is an
authorization-delegation framework. So "follow the standard" means: carry context in claims, reuse
registered claim names, and add no new endpoints.

| Need | Standard | Notes |
|---|---|---|
| Identify the person | `sub` — OIDC Core | Stable and global. Never varies by org or app |
| Say what the token is for | `aud` — OAuth 2.0 | Per-application resource, see [Audience isolation](#audience-isolation) |
| Say what the app may do | `scope` — OAuth 2.0 | Already in use |
| Say who asked | `client_id` / `azp` | Already in use |
| Carry authorization facts | `roles` — **RFC 9068** | Registered for JWT access tokens, alongside `groups` and `entitlements`. Tokens already carry `"typ": "at+jwt"` from this RFC |
| Target a specific API | `resource` — **RFC 8707** | Optional; useful once each app has its own audience |
| Identify the company | — | **No registered claim exists.** Conventions are Azure AD's `tid` and Auth0's `org_id` |

`org_id` is the only genuine extension. Everything else is adoption.

---

## Schema

Four new tables. `Users`, `Tenants` and the Identity role tables are unchanged.

| Table | Columns | Purpose |
|---|---|---|
| `TenantMemberships` | `Id`, `TenantId`, `UserId`, `IsActive`, `CreatedAt` | Who belongs to which company. Unique on `(TenantId, UserId)` |
| `TenantMembershipRoles` | `MembershipId`, `Role` | Company-level roles, e.g. `OrgAdmin`, `Member` |
| `TenantApplications` | `TenantId`, `ClientId`, `IsActive`, `CreatedAt` | Which applications a company subscribes to. Unique on `(TenantId, ClientId)` |
| `MembershipApplicationRoles` | `MembershipId`, `ClientId`, `Role` | Optional per-application roles for one member |

Roles are rows, not delimited strings — they get queried, indexed and audited.

`ClientId` is the OpenIddict client identifier (a string), not a foreign key into
`OpenIddictApplications`. OpenIddict owns that table; referencing it by value avoids coupling your
schema to its migrations.

---

## Effective roles

A token is issued for exactly one `(user, company, application)` triple. Its `roles` claim is
resolved server-side into a single flat list:

```
roles = TenantMembershipRoles(user, org)
      ∪ MembershipApplicationRoles(user, org, client)
```

Resolving to one claim matters: a resource server should never have to read three role claims and
re-derive precedence. That logic lives in `ConnectService`, once, where it can be tested.

### Platform roles are deliberately excluded

The global Identity roles (`Admin`) do **not** flow into a company-context token.

A platform administrator who authorizes into Acme Corp's application receives Acme's roles and
nothing more. Being staff does not silently confer authority inside a customer's tenancy — which
is exactly the property you want when someone's account is compromised, and the property that makes
audit logs meaningful ("who did this in Acme?" has one answer, not "anyone with platform admin").

Platform roles appear only in tokens issued for the auth server's own admin API. Staff who
genuinely need to act inside a company get an explicit membership, which is visible and revocable.
If you later want break-glass access, add it as an explicit, audited elevation — not as an implicit
side effect of a role name.

---

## Token shape

```jsonc
{
  "sub":       "e525dfb3-…",        // the person — identical across every org and app
  "org_id":    "9a41…",             // active company context
  "org_slug":  "acme-corp",         // convenience for resource servers and logs
  "client_id": "acme-invoicing",
  "aud":       "acme-invoicing-api",
  "scope":     "openid profile email invoicing.api",
  "roles":     ["OrgAdmin", "Invoicing.Approver"]
}
```

**One company per token.** A user belonging to three companies authorizes into one at a time;
switching is a new authorization request. This is how Azure AD and Auth0 Organizations behave. The
alternative — every membership in one token — breaks least privilege, makes `aud` and `roles`
ambiguous, and grows unboundedly with the customer's org chart.

---

## Enforcement points

### `/connect/authorize`

Currently [ConnectController.cs:41-45](../src/AuthServer/AuthServer.API/Controllers/ConnectController.cs#L41-L45)
resolves the user and builds an identity. It gains four steps:

1. **Resolve the company.** Read `organization` from the request — OpenIddict passes unknown
   parameters through via `request.GetParameter("organization")`. If absent and the user has
   exactly one active membership, use it. If absent and they have several, show a company picker
   (the auth server hosts the login UI already, so this is a page, not a protocol change).
2. **Verify membership** — active membership in an active tenant, else `Forbid` with
   `Errors.AccessDenied`.
3. **Verify subscription** — the company subscribes to *this* `client_id`, else `access_denied`.
   This is where "application user" is enforced, and it is the whole nesting rule in one check.
4. **Build the identity** with `org_id`, `org_slug` and resolved `roles`.

OpenIddict persists those claims into the authorization code, so they reach the token with no
further work.

### `/connect/token` — refresh

[ConnectService.cs:74-95](../src/PixSmith.Authorization.Services/ConnectService.cs#L74-L95) already
re-reads roles from the store rather than trusting the incoming principal. Extend it to re-check
membership and subscription, and to re-resolve roles for the org carried in the principal.

Without this, revoking a membership does nothing until every outstanding refresh token expires.
With it, revocation takes effect at the next refresh.

### Client credentials

No user, so there is no membership to consult. A machine client belongs to exactly one company:
look up its `TenantApplications` row and emit that `org_id`. A machine client subscribed to no
company gets no `org_id` and should be treated as platform-level.

### Resource servers

Unchanged in shape: validate `aud` and `scope` as
[INTEGRATION.md](../INTEGRATION.md) already describes, then authorize on `org_id` + `roles`. The
important new rule for integrators: **scope every query by `org_id`.** A token proves which company
the caller is acting for; ignoring that claim reintroduces exactly the cross-tenant data leak the
model exists to prevent.

---

## Audience isolation

This design forces a fix that is currently outstanding. `EnsureScopeAsync` in
[OpenIddictSeeder.cs:129](../src/AuthServer/AuthServer.Infrastructure/OpenIddict/OpenIddictSeeder.cs#L129)
hardcodes `Resources = { "resource-server" }`, so every scope maps to the same audience and a token
minted for one application is audience-valid at every other.

With per-application entitlements that becomes a real boundary rather than a theoretical one: give
each application its own scope and resource name, so `aud` identifies one API. Take the resource
name as a parameter instead of hardcoding it.

---

## Rollout

The database currently holds **1 user, 0 tenants, 3 clients**. Switching enforcement on with zero
memberships would deny every authorization request, so the rollout needs a backfill.

1. **Migrations** — four tables, generated for *both* providers (`…Migrations.Sqlite` and
   `…Migrations.Postgres`). The build fails silently on the wrong one if you forget.
2. **Backfill** — create a `default` tenant, add every existing user as a member, subscribe every
   existing client. Deterministic, one-time, and leaves no permanent "if no tenants exist, skip the
   check" branch in the authorization path. Conditional security is how enforcement quietly stops
   applying.
3. **Enforce** — turn on the authorize-time checks once the backfill has run.

> **The backfill bypasses the provisioning control, and that is expected.**
> [TENANT-PROVISIONING.md](TENANT-PROVISIONING.md) gates the HTTP endpoints; a migration running
> in-process is not an HTTP request. The control's threat model is "no application can provision a
> tenancy for itself over the API" — it has never claimed to stop something that already has
> database access, which is why the trust anchor lives in configuration rather than in the
> database. Keep the backfill a one-time migration, not a reusable seeding capability.

---

## Suggested staging

Each stage is independently shippable and leaves the system working.

| Stage | Contents | Risk |
|---|---|---|
| 1 | Schema, EF entities, repositories, both migrations. No behaviour change | Low — nothing reads it yet |
| 2 | Admin API + Blazor pages for memberships and subscriptions | Low |
| 3 | Backfill migration (default tenant, existing users and clients) | Low, but do it before stage 4 |
| 4 | Claim emission — `org_id`, `org_slug`, `roles` — plus `GetDestinations` entries | Medium: see the gotcha below |
| 5 | Authorize-time enforcement + refresh re-validation | **High** — this is where sign-ins start being refused |
| 6 | Per-application scopes and resources (audience isolation) | Medium — needs integrated apps to update their expected `aud` |

### The gotcha in stage 4

`GetDestinations` in
[ConnectService.cs:148](../src/PixSmith.Authorization.Services/ConnectService.cs#L148) is an
allowlist. A claim not named there is **silently dropped** from the access token — no error, no
warning, just a claim that never arrives. Add `org_id` and `org_slug` there in the same change that
starts emitting them.

---

## Open questions

- **Company picker UX.** When a user belongs to several companies and the client sends no
  `organization` parameter, do they choose at login, or must every client specify one? A picker is
  friendlier; requiring the parameter is simpler and more explicit.
- **Per-member application overrides.** `MembershipApplicationRoles` supports per-app roles. Do you
  also need to *deny* a member an app their company subscribes to? That is a fourth state and worth
  skipping until something demands it.
- **Invitations.** Adding a member to a company is an admin action today. If customers self-manage
  their users, that needs an invitation flow with its own token type.
- **Does an `OrgAdmin` manage their own company's memberships?** If so, the admin API needs
  org-scoped authorization, not just the platform-level `AdminAccess` policy it uses now.
