using Microsoft.Extensions.Logging.Abstractions;
using PixSmith.Authorization.Domain.Entities;
using PixSmith.Authorization.Repositories;
using PixSmith.Authorization.Services;
using Xunit;

namespace PixSmith.Authorization.UnitTests.Services;

/// <summary>
/// Stage 4 of docs/MULTI-TENANCY.md — working out which company a token is for.
///
/// <para>
/// The central rule under test: an unresolvable context returns <c>null</c>, it does not throw
/// and it does not deny. Stage 4 emits claims; stage 5 is where an unresolved context starts
/// refusing sign-ins. Conflating the two would make enforcement impossible to switch on
/// independently.
/// </para>
/// </summary>
public sealed class TenantContextResolverTests : IDisposable
{
    private readonly SqliteTestDb _db = new();

    private TenantContextResolver Build() => new(
        new TenantRepository(_db.Context),
        new TenantMembershipRepository(_db.Context),
        new TenantApplicationRepository(_db.Context),
        NullLogger<TenantContextResolver>.Instance);

    private async Task<Tenant> SeedTenantAsync(string name, bool active = true)
    {
        var tenant = Tenant.Create(name, null);
        if (!active) tenant.Deactivate();
        await new TenantRepository(_db.Context).AddAsync(tenant);
        return tenant;
    }

    private async Task<TenantMembership> SeedMembershipAsync(
        Guid tenantId, Guid userId, bool active = true, params string[] roles)
    {
        var membership = TenantMembership.Create(tenantId, userId, roles);
        if (!active) membership.Deactivate();
        await new TenantMembershipRepository(_db.Context).AddAsync(membership);
        return membership;
    }

    // ── Resolution for a user ─────────────────────────────────────────────────

    [Fact]
    public async Task A_sole_membership_resolves_without_an_organization_parameter()
    {
        var tenant = await SeedTenantAsync("Acme Corp");
        var userId = Guid.NewGuid();
        await SeedMembershipAsync(tenant.Id, userId, true, "OrgAdmin");

        var context = await Build().ResolveForUserAsync(userId, "invoicing", null);

        Assert.NotNull(context);
        Assert.Equal(tenant.Id, context!.TenantId);
        Assert.Equal("acme-corp", context.Slug);
        Assert.Equal(["OrgAdmin"], context.Roles);
    }

    [Fact]
    public async Task Several_memberships_without_a_parameter_are_ambiguous()
    {
        // Picking one arbitrarily would issue a token whose authority the caller never chose.
        var acme = await SeedTenantAsync("Acme Corp");
        var globex = await SeedTenantAsync("Globex");
        var userId = Guid.NewGuid();
        await SeedMembershipAsync(acme.Id, userId, true, "Member");
        await SeedMembershipAsync(globex.Id, userId, true, "Member");

        Assert.Null(await Build().ResolveForUserAsync(userId, null, null));
    }

    [Theory]
    [InlineData(true)]   // by slug
    [InlineData(false)]  // by tenant id
    public async Task An_explicit_organization_selects_among_several(bool bySlug)
    {
        var acme = await SeedTenantAsync("Acme Corp");
        var globex = await SeedTenantAsync("Globex");
        var userId = Guid.NewGuid();
        await SeedMembershipAsync(acme.Id, userId, true, "OrgAdmin");
        await SeedMembershipAsync(globex.Id, userId, true, "Member");

        var requested = bySlug ? "globex" : globex.Id.ToString();
        var context = await Build().ResolveForUserAsync(userId, null, requested);

        Assert.Equal(globex.Id, context!.TenantId);
        Assert.Equal(["Member"], context.Roles);
    }

    [Fact]
    public async Task A_company_the_user_does_not_belong_to_resolves_to_null()
    {
        // Stage 4 omits the claims; stage 5 turns this into access_denied.
        var acme = await SeedTenantAsync("Acme Corp");
        var globex = await SeedTenantAsync("Globex");
        var userId = Guid.NewGuid();
        await SeedMembershipAsync(acme.Id, userId, true, "Member");

        Assert.Null(await Build().ResolveForUserAsync(userId, null, globex.Slug));
    }

    [Fact]
    public async Task A_user_with_no_memberships_resolves_to_null_rather_than_throwing()
    {
        // A legitimate state: platform-only staff, or a self-registered user awaiting invite.
        Assert.Null(await Build().ResolveForUserAsync(Guid.NewGuid(), "invoicing", null));
    }

    [Fact]
    public async Task An_inactive_membership_is_not_a_candidate()
    {
        var tenant = await SeedTenantAsync("Acme Corp");
        var userId = Guid.NewGuid();
        await SeedMembershipAsync(tenant.Id, userId, active: false, "OrgAdmin");

        Assert.Null(await Build().ResolveForUserAsync(userId, null, null));
    }

    [Fact]
    public async Task Deactivating_the_company_removes_the_context()
    {
        // Suspending a customer must take effect without touching each membership row.
        var tenant = await SeedTenantAsync("Acme Corp", active: false);
        var userId = Guid.NewGuid();
        await SeedMembershipAsync(tenant.Id, userId, true, "OrgAdmin");

        Assert.Null(await Build().ResolveForUserAsync(userId, null, null));
    }

    [Fact]
    public async Task Roles_are_resolved_for_the_requesting_application()
    {
        var tenant = await SeedTenantAsync("Acme Corp");
        var userId = Guid.NewGuid();
        var membership = TenantMembership.Create(tenant.Id, userId, ["Member"]);
        membership.AssignApplicationRole("invoicing", "Approver");
        await new TenantMembershipRepository(_db.Context).AddAsync(membership);

        var sut = Build();
        Assert.Equal(["Approver", "Member"],
            (await sut.ResolveForUserAsync(userId, "invoicing", null))!.Roles.Order());
        Assert.Equal(["Member"],
            (await sut.ResolveForUserAsync(userId, "payroll", null))!.Roles);
    }

    // ── Resolution for a machine client ───────────────────────────────────────

    [Fact]
    public async Task A_client_subscribed_by_one_company_resolves_to_it()
    {
        var tenant = await SeedTenantAsync("Acme Corp");
        await new TenantApplicationRepository(_db.Context)
            .AddAsync(TenantApplication.Create(tenant.Id, "reporting-service"));

        var context = await Build().ResolveForClientAsync("reporting-service");

        Assert.Equal(tenant.Id, context!.TenantId);
        Assert.Empty(context.Roles);   // no user, so no membership roles
    }

    [Fact]
    public async Task A_client_subscribed_by_several_companies_is_ambiguous()
    {
        var acme = await SeedTenantAsync("Acme Corp");
        var globex = await SeedTenantAsync("Globex");
        var repo = new TenantApplicationRepository(_db.Context);
        await repo.AddAsync(TenantApplication.Create(acme.Id, "shared-service"));
        await repo.AddAsync(TenantApplication.Create(globex.Id, "shared-service"));

        Assert.Null(await Build().ResolveForClientAsync("shared-service"));
    }

    [Fact]
    public async Task An_unsubscribed_client_resolves_to_null()
    {
        await SeedTenantAsync("Acme Corp");
        Assert.Null(await Build().ResolveForClientAsync("nobody-subscribes"));
    }

    public void Dispose() => _db.Dispose();
}
