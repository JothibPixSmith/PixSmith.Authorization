# Multi-Tenancy Design

**Status: stages 1–5 built, 6 outstanding.** Tokens carry `org_id`, `org_slug` and `roles`,
and the nesting rule is enforced: a member may reach an application when their company
subscribes to it, checked at `/connect/authorize` and again on every refresh. Only audience
isolation (stage 6) remains. See the [staging table](#suggested-staging).

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

> **Implementation note — the claim is `roles`, not `role`.** This document originally implied
> reusing the existing singular `role` claim. Stage 4 deliberately did not: the `AdminAccess`
> policy reads `role` for `"Admin"`, and an administrator's *company* roles are `Member` and
> `OrgAdmin`. Overloading `role` would have locked administrators out of the admin API the
> moment a company context resolved. Company roles therefore use the plural `roles` claim —
> which is the name RFC 9068 actually registers — while `role` continues to carry platform
> roles unchanged. `role` can be retired once no resource server depends on it.

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

### Platform clients are exempt

`TenantEnforcement:PlatformClients` lists clients that administer the auth server itself rather
than a company's data — the admin UI above all. They skip the membership and subscription
checks, though a company context is still attached when one resolves.

The exemption exists because "administer the authorization server" is not a tenant-scoped
activity. Without it, platform staff would need a membership of some company merely to reach
the admin UI — which would make membership mean two different things and hand every
administrator standing access inside a customer's tenancy, the exact property
[the roles section](#platform-roles-are-deliberately-excluded) exists to prevent.

It lives in configuration, not the database: an exemption from an access-control check should
not be editable by anything holding only a database connection. Keep the list short, and never
add a customer-facing client to it.

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

That hardcode is now removed, and scopes are managed at runtime through
`/api/admin/oidc-scopes` so onboarding an application needs no redeploy. A scope stored in the
database works without being listed in `RegisterScopes()` at startup — verified — which is what
makes runtime management viable.

Isolation arrives in three steps, and only the third delivers it:

1. **Additive** — create the per-application scope and grant it *alongside* the existing `api`.
   Tokens carry both audiences, so nothing breaks. ✅ done for `jamtools.api`.
2. **Migrate** — the resource server switches to the new audience. Still passing, because the
   token carries both.
3. **Remove** — drop `api` from the client, leaving one audience.

Stopping after step 2 leaves every token still audience-valid at every other application.

---

## Rollout

The database currently holds **1 user, 0 tenants, 3 clients**. Switching enforcement on with zero
memberships would deny every authorization request, so the rollout needs a backfill.

1. **Migrations** — four tables, generated for *both* providers (`…Migrations.Sqlite` and
   `…Migrations.Postgres`). The build fails silently on the wrong one if you forget. ✅
2. **Backfill** — `TenantBackfillSeeder` creates a `Default` tenancy, adds every existing user as a
   member, and subscribes every registered client. It leaves no permanent "if no tenants exist, skip
   the check" branch in the authorization path — conditional security is how enforcement quietly
   stops applying. ✅

   Two guards bound it, and both matter more than the happy path:

   - **Any tenancy already exists → skip.** Re-running against a live system would sweep every user
     into a company, including people deliberately removed from it.
   - **No users exist → skip.** A fresh install gains tenancies through the signed provisioning
     flow; an empty default would be clutter that also suppresses the seeder forever.

   Users holding the platform `Admin` role additionally receive `OrgAdmin` in the migrated tenancy,
   so whoever administered the system beforehand can still administer where they land. After the
   backfill that authority comes from the explicit membership, not from being staff — configurable
   via `TenantBackfill:MemberRole` and `TenantBackfill:AdminRole`.
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
| 1 | ✅ **Done** — schema, EF entities, repositories, both migrations | Low — nothing reads it yet |
| 2 | ✅ **Done** — admin API + Blazor pages for memberships and subscriptions | Low |
| 3 | ✅ **Done** — backfill seeder (default tenant, existing users and clients) | Low, but do it before stage 4 |
| 4 | ✅ **Done** — claim emission: `org_id`, `org_slug`, `roles`, plus `GetDestinations` entries | Medium: see the gotcha below |
| 5 | ✅ **Done** — authorize-time enforcement + refresh re-validation | **High** — this is where sign-ins start being refused |
| 6 | 🟡 **Step 1 of 3 done** — scope management + per-app scopes exist and are additive; integrated apps have not yet migrated their `aud` | Medium — needs integrated apps to update their expected `aud` |

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
