using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PixSmith.Authorization.Domain.Entities;
using PixSmith.Authorization.Repositories;
using PixSmith.Authorization.Services;
using Xunit;

namespace PixSmith.Authorization.UnitTests.Services;

/// <summary>
/// Stage 5 of docs/MULTI-TENANCY.md — the point at which sign-ins start being refused.
/// The denial paths carry the weight here: each one is a way someone could be locked out,
/// or wrongly let in.
/// </summary>
public sealed class TenantAccessPolicyTests : IDisposable
{
    private readonly SqliteTestDb _db = new();

    private TenantAccessPolicy Build(params string[] platformClients)
    {
        var repos = (
            tenants: new TenantRepository(_db.Context),
            memberships: new TenantMembershipRepository(_db.Context),
            subscriptions: new TenantApplicationRepository(_db.Context));

        return new TenantAccessPolicy(
            new TenantContextResolver(repos.tenants, repos.memberships, repos.subscriptions,
                NullLogger<TenantContextResolver>.Instance),
            repos.memberships, repos.tenants, repos.subscriptions,
            Options.Create(new TenantEnforcementOptions { PlatformClients = [.. platformClients] }),
            NullLogger<TenantAccessPolicy>.Instance);
    }

    private async Task<Tenant> SeedTenantAsync(string name)
    {
        var tenant = Tenant.Create(name, null);
        await new TenantRepository(_db.Context).AddAsync(tenant);
        return tenant;
    }

    private Task SeedMembershipAsync(Guid tenantId, Guid userId, params string[] roles) =>
        new TenantMembershipRepository(_db.Context)
            .AddAsync(TenantMembership.Create(tenantId, userId, roles));

    private Task SubscribeAsync(Guid tenantId, string clientId) =>
        new TenantApplicationRepository(_db.Context)
            .AddAsync(TenantApplication.Create(tenantId, clientId));

    // ── Allowed ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_member_of_a_subscribed_company_is_allowed()
    {
        var tenant = await SeedTenantAsync("Acme Corp");
        var userId = _db.NewUser();
        await SeedMembershipAsync(tenant.Id, userId, "OrgAdmin");
        await SubscribeAsync(tenant.Id, "invoicing");

        var decision = await Build().EvaluateForUserAsync(userId, "invoicing", null);

        Assert.True(decision.IsAllowed);
        Assert.Equal(tenant.Id, decision.Context!.TenantId);
        Assert.Equal(["OrgAdmin"], decision.Context.Roles);
    }

    // ── The nesting rule ──────────────────────────────────────────────────────

    [Fact]
    public async Task A_member_whose_company_is_not_subscribed_is_denied()
    {
        // The whole nesting rule in one test: membership alone is not access.
        var tenant = await SeedTenantAsync("Acme Corp");
        var userId = _db.NewUser();
        await SeedMembershipAsync(tenant.Id, userId, "OrgAdmin");
        // deliberately no subscription

        var decision = await Build().EvaluateForUserAsync(userId, "invoicing", null);

        Assert.False(decision.IsAllowed);
        Assert.Contains("not subscribed", decision.Error);
    }

    [Fact]
    public async Task Suspending_the_subscription_denies_every_member_at_once()
    {
        var tenant = await SeedTenantAsync("Acme Corp");
        var userId = _db.NewUser();
        await SeedMembershipAsync(tenant.Id, userId, "Member");

        var subscriptions = new TenantApplicationRepository(_db.Context);
        var subscription = TenantApplication.Create(tenant.Id, "invoicing");
        await subscriptions.AddAsync(subscription);
        subscription.Deactivate();
        await subscriptions.UpdateAsync(subscription);

        Assert.False((await Build().EvaluateForUserAsync(userId, "invoicing", null)).IsAllowed);
    }

    [Fact]
    public async Task One_companys_subscription_does_not_grant_another_company_access()
    {
        var acme = await SeedTenantAsync("Acme Corp");
        var globex = await SeedTenantAsync("Globex");
        var userId = _db.NewUser();
        await SeedMembershipAsync(globex.Id, userId, "Member");
        await SubscribeAsync(acme.Id, "invoicing");   // Acme subscribes, not Globex

        Assert.False((await Build().EvaluateForUserAsync(userId, "invoicing", null)).IsAllowed);
    }

    // ── Denials that must stay recoverable ────────────────────────────────────

    [Fact]
    public async Task A_user_with_no_membership_is_denied_with_a_clear_reason()
    {
        var decision = await Build().EvaluateForUserAsync(Guid.NewGuid(), "invoicing", null);

        Assert.False(decision.IsAllowed);
        Assert.Contains("not a member of any active organization", decision.Error);
    }

    [Fact]
    public async Task An_ambiguous_request_names_the_users_own_organizations()
    {
        // A bare "access denied" here would be a dead end — the caller has to know they must
        // choose, and what the choices are. These are the caller's own memberships, so naming
        // them reveals nothing they did not already know.
        var acme = await SeedTenantAsync("Acme Corp");
        var globex = await SeedTenantAsync("Globex");
        var userId = _db.NewUser();
        await SeedMembershipAsync(acme.Id, userId, "Member");
        await SeedMembershipAsync(globex.Id, userId, "Member");
        await SubscribeAsync(acme.Id, "invoicing");
        await SubscribeAsync(globex.Id, "invoicing");

        var decision = await Build().EvaluateForUserAsync(userId, "invoicing", null);

        Assert.False(decision.IsAllowed);
        Assert.Contains("organization", decision.Error);
        Assert.Contains("acme-corp", decision.Error);
        Assert.Contains("globex", decision.Error);
    }

    [Fact]
    public async Task Requesting_a_company_you_do_not_belong_to_reveals_nothing_about_it()
    {
        var acme = await SeedTenantAsync("Acme Corp");
        var globex = await SeedTenantAsync("Globex");
        var userId = _db.NewUser();
        await SeedMembershipAsync(acme.Id, userId, "Member");
        await SubscribeAsync(globex.Id, "invoicing");

        var decision = await Build().EvaluateForUserAsync(userId, "invoicing", "globex");

        Assert.False(decision.IsAllowed);
        // Must not confirm or deny that "globex" exists, or say anything about it.
        Assert.DoesNotContain("Globex", decision.Error);
        Assert.Contains("not a member of the requested organization", decision.Error);
    }

    // ── Per-member denial ─────────────────────────────────────────────────────

    [Fact]
    public async Task An_individually_denied_member_is_refused_a_subscribed_application()
    {
        var tenant = await SeedTenantAsync("Acme Corp");
        var userId = _db.NewUser();
        await SubscribeAsync(tenant.Id, "invoicing");

        var membership = TenantMembership.Create(tenant.Id, userId, ["Member"]);
        membership.DenyApplication("invoicing", "Not authorised");
        await new TenantMembershipRepository(_db.Context).AddAsync(membership);

        var decision = await Build().EvaluateForUserAsync(userId, "invoicing", null);

        Assert.False(decision.IsAllowed);
        // The administrative reason must not reach the denied user.
        Assert.DoesNotContain("Not authorised", decision.Error);
    }

    [Fact]
    public async Task A_denial_affects_only_the_named_application()
    {
        var tenant = await SeedTenantAsync("Acme Corp");
        var userId = _db.NewUser();
        await SubscribeAsync(tenant.Id, "invoicing");
        await SubscribeAsync(tenant.Id, "payroll");

        var membership = TenantMembership.Create(tenant.Id, userId, ["Member"]);
        membership.DenyApplication("invoicing");
        await new TenantMembershipRepository(_db.Context).AddAsync(membership);

        var policy = Build();
        Assert.False((await policy.EvaluateForUserAsync(userId, "invoicing", null)).IsAllowed);
        Assert.True((await policy.EvaluateForUserAsync(userId, "payroll", null)).IsAllowed);
    }

    [Fact]
    public async Task A_denial_affects_only_the_named_member()
    {
        // The whole reason a denial is per-member rather than a suspended subscription:
        // colleagues must keep working.
        var tenant = await SeedTenantAsync("Acme Corp");
        var denied = _db.NewUser();
        var colleague = _db.NewUser();
        await SubscribeAsync(tenant.Id, "invoicing");

        var repo = new TenantMembershipRepository(_db.Context);
        var m1 = TenantMembership.Create(tenant.Id, denied, ["Member"]);
        m1.DenyApplication("invoicing");
        await repo.AddAsync(m1);
        await repo.AddAsync(TenantMembership.Create(tenant.Id, colleague, ["Member"]));

        var policy = Build();
        Assert.False((await policy.EvaluateForUserAsync(denied, "invoicing", null)).IsAllowed);
        Assert.True((await policy.EvaluateForUserAsync(colleague, "invoicing", null)).IsAllowed);
    }

    [Fact]
    public async Task Restoring_access_reverses_a_denial()
    {
        var tenant = await SeedTenantAsync("Acme Corp");
        var userId = _db.NewUser();
        await SubscribeAsync(tenant.Id, "invoicing");

        var repo = new TenantMembershipRepository(_db.Context);
        var membership = TenantMembership.Create(tenant.Id, userId, ["Member"]);
        membership.DenyApplication("invoicing");
        await repo.AddAsync(membership);

        Assert.False((await Build().EvaluateForUserAsync(userId, "invoicing", null)).IsAllowed);

        membership.AllowApplication("invoicing");
        await repo.UpdateAsync(membership);

        Assert.True((await Build().EvaluateForUserAsync(userId, "invoicing", null)).IsAllowed);
    }

    [Fact]
    public async Task A_denial_survives_a_general_role_update()
    {
        // Denials are managed through their own endpoint; editing roles must not silently
        // restore access someone deliberately removed.
        var tenant = await SeedTenantAsync("Acme Corp");
        var userId = _db.NewUser();
        await SubscribeAsync(tenant.Id, "invoicing");

        var repo = new TenantMembershipRepository(_db.Context);
        var membership = TenantMembership.Create(tenant.Id, userId, ["Member"]);
        membership.DenyApplication("invoicing");
        await repo.AddAsync(membership);

        var reloaded = await repo.GetAsync(tenant.Id, userId);
        Assert.True(reloaded!.IsDeniedApplication("invoicing"));

        reloaded.AssignRole("Auditor");
        await repo.UpdateAsync(reloaded);

        Assert.False((await Build().EvaluateForUserAsync(userId, "invoicing", null)).IsAllowed);
    }

    // ── Platform clients ──────────────────────────────────────────────────────

    [Fact]
    public async Task A_platform_client_is_reachable_without_any_membership()
    {
        // Administering the auth server is not a tenant-scoped activity. Without this,
        // platform-only staff could not reach the admin UI at all.
        var decision = await Build("blazor-client")
            .EvaluateForUserAsync(Guid.NewGuid(), "blazor-client", null);

        Assert.True(decision.IsAllowed);
        Assert.Null(decision.Context);
    }

    [Fact]
    public async Task A_platform_client_still_carries_a_company_context_when_one_resolves()
    {
        var tenant = await SeedTenantAsync("Acme Corp");
        var userId = _db.NewUser();
        await SeedMembershipAsync(tenant.Id, userId, "OrgAdmin");

        var decision = await Build("blazor-client")
            .EvaluateForUserAsync(userId, "blazor-client", null);

        Assert.True(decision.IsAllowed);
        Assert.Equal(["OrgAdmin"], decision.Context!.Roles);
    }

    [Fact]
    public async Task The_platform_exemption_does_not_leak_to_other_clients()
    {
        var tenant = await SeedTenantAsync("Acme Corp");
        var userId = _db.NewUser();
        await SeedMembershipAsync(tenant.Id, userId, "Member");

        var policy = Build("blazor-client");

        Assert.True((await policy.EvaluateForUserAsync(userId, "blazor-client", null)).IsAllowed);
        Assert.False((await policy.EvaluateForUserAsync(userId, "invoicing", null)).IsAllowed);
    }

    [Fact]
    public async Task Platform_client_matching_is_case_insensitive_but_not_partial()
    {
        var policy = Build("blazor-client");

        Assert.True((await policy.EvaluateForUserAsync(Guid.NewGuid(), "BLAZOR-CLIENT", null)).IsAllowed);
        // A prefix must not inherit the exemption — "blazor-client-evil" is a different client.
        Assert.False((await policy.EvaluateForUserAsync(Guid.NewGuid(), "blazor-client-evil", null)).IsAllowed);
    }

    [Fact]
    public async Task With_no_platform_clients_configured_nothing_is_exempt()
    {
        Assert.False((await Build().EvaluateForUserAsync(Guid.NewGuid(), "blazor-client", null)).IsAllowed);
    }

    public void Dispose() => _db.Dispose();
}
