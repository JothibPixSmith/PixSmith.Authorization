using Microsoft.EntityFrameworkCore;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Domain.Entities;
using PixSmith.Authorization.Repositories;
using Xunit;

namespace PixSmith.Authorization.UnitTests.Services;

/// <summary>
/// Stage 1 of docs/MULTI-TENANCY.md — schema and persistence only. Nothing here asserts
/// authorization behaviour, because nothing reads these tables yet.
/// </summary>
public sealed class TenantMembershipTests : IDisposable
{
    private readonly SqliteTestDb _db = new();

    private async Task<Guid> SeedTenantAsync(string name = "Acme Corp")
    {
        var tenant = Tenant.Create(name, null);
        await new TenantRepository(_db.Context).AddAsync(tenant);
        return tenant.Id;
    }

    // ── Effective roles: the shape of the future `roles` claim ────────────────

    [Fact]
    public void Effective_roles_union_company_and_application_roles()
    {
        var membership = TenantMembership.Create(Guid.NewGuid(), Guid.NewGuid(), ["OrgAdmin"]);
        membership.AssignApplicationRole("invoicing", "Approver");

        Assert.Equal(["OrgAdmin", "Approver"], membership.EffectiveRoles("invoicing").OrderDescending());
    }

    [Fact]
    public void Application_roles_do_not_leak_between_applications()
    {
        // The whole point of per-application roles: an Approver in invoicing must not be an
        // Approver in payroll.
        var membership = TenantMembership.Create(Guid.NewGuid(), Guid.NewGuid(), ["Member"]);
        membership.AssignApplicationRole("invoicing", "Approver");

        Assert.Contains("Approver", membership.EffectiveRoles("invoicing"));
        Assert.DoesNotContain("Approver", membership.EffectiveRoles("payroll"));
        Assert.Contains("Member", membership.EffectiveRoles("payroll"));
    }

    [Fact]
    public void Effective_roles_with_no_application_context_are_company_roles_only()
    {
        var membership = TenantMembership.Create(Guid.NewGuid(), Guid.NewGuid(), ["Member"]);
        membership.AssignApplicationRole("invoicing", "Approver");

        Assert.Equal(["Member"], membership.EffectiveRoles(null));
    }

    [Fact]
    public void Roles_are_case_insensitive_and_deduplicated()
    {
        var membership = TenantMembership.Create(Guid.NewGuid(), Guid.NewGuid(), ["OrgAdmin"]);
        membership.AssignRole("orgadmin");

        Assert.Single(membership.Roles);
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    [Fact]
    public async Task Membership_round_trips_with_both_role_kinds()
    {
        var tenantId = await SeedTenantAsync();
        var userId = _db.NewUser();
        var repo = new TenantMembershipRepository(_db.Context);

        var membership = TenantMembership.Create(tenantId, userId, ["OrgAdmin", "Member"]);
        membership.AssignApplicationRole("invoicing", "Approver");
        await repo.AddAsync(membership);

        var loaded = await repo.GetAsync(tenantId, userId);

        Assert.NotNull(loaded);
        Assert.Equal(["Member", "OrgAdmin"], loaded!.Roles.Order());
        Assert.Equal(["Approver"], loaded.ApplicationRoles["invoicing"]);
    }

    [Fact]
    public async Task Update_replaces_roles_rather_than_accumulating_them()
    {
        // A revoked role must actually disappear. Diff-based updates are where stale grants
        // survive; this repository replaces the set wholesale.
        var tenantId = await SeedTenantAsync();
        var userId = _db.NewUser();
        var repo = new TenantMembershipRepository(_db.Context);

        var membership = TenantMembership.Create(tenantId, userId, ["OrgAdmin"]);
        await repo.AddAsync(membership);

        membership.RemoveRole("OrgAdmin");
        membership.AssignRole("Member");
        await repo.UpdateAsync(membership);

        var loaded = await repo.GetAsync(tenantId, userId);
        Assert.Equal(["Member"], loaded!.Roles);
    }

    [Fact]
    public async Task A_user_cannot_hold_two_memberships_of_one_company()
    {
        var tenantId = await SeedTenantAsync();
        var userId = _db.NewUser();
        var repo = new TenantMembershipRepository(_db.Context);

        await repo.AddAsync(TenantMembership.Create(tenantId, userId));

        // Enforced by a unique index, so two concurrent invitations cannot both succeed.
        await Assert.ThrowsAnyAsync<DbUpdateException>(
            () => repo.AddAsync(TenantMembership.Create(tenantId, userId)));
    }

    [Fact]
    public async Task One_user_can_belong_to_several_companies()
    {
        var acme = await SeedTenantAsync("Acme Corp");
        var globex = await SeedTenantAsync("Globex");
        var userId = _db.NewUser();
        var repo = new TenantMembershipRepository(_db.Context);

        await repo.AddAsync(TenantMembership.Create(acme, userId, ["OrgAdmin"]));
        await repo.AddAsync(TenantMembership.Create(globex, userId, ["Member"]));

        var memberships = (await repo.GetForUserAsync(userId)).ToList();

        Assert.Equal(2, memberships.Count);
        Assert.Equal(["Member", "OrgAdmin"], memberships.SelectMany(m => m.Roles).Order());
    }

    [Fact]
    public async Task Deleting_a_company_removes_its_memberships_and_roles()
    {
        // Otherwise a deleted company leaves rows behind that would keep granting access if
        // its id were ever reused.
        var tenantId = await SeedTenantAsync();
        var membership = TenantMembership.Create(tenantId, _db.NewUser(), ["OrgAdmin"]);
        membership.AssignApplicationRole("invoicing", "Approver");
        await new TenantMembershipRepository(_db.Context).AddAsync(membership);

        await new TenantRepository(_db.Context).DeleteAsync(tenantId);

        Assert.Empty(await _db.Context.TenantMemberships.ToListAsync());
        Assert.Empty(await _db.Context.TenantMembershipRoles.ToListAsync());
        Assert.Empty(await _db.Context.MembershipApplicationRoles.ToListAsync());
    }

    // ── Subscriptions ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Subscription_round_trips_and_reports_as_subscribed()
    {
        var tenantId = await SeedTenantAsync();
        var repo = new TenantApplicationRepository(_db.Context);

        await repo.AddAsync(TenantApplication.Create(tenantId, "invoicing"));

        Assert.True(await repo.IsSubscribedAsync(tenantId, "invoicing"));
        Assert.False(await repo.IsSubscribedAsync(tenantId, "payroll"));
    }

    [Fact]
    public async Task Deactivating_a_subscription_revokes_it()
    {
        var tenantId = await SeedTenantAsync();
        var repo = new TenantApplicationRepository(_db.Context);

        var subscription = TenantApplication.Create(tenantId, "invoicing");
        await repo.AddAsync(subscription);

        subscription.Deactivate();
        await repo.UpdateAsync(subscription);

        Assert.False(await repo.IsSubscribedAsync(tenantId, "invoicing"));
    }

    [Fact]
    public async Task Deactivating_the_company_revokes_every_subscription_at_once()
    {
        // Suspending a customer must not require touching each subscription row.
        var tenantRepo = new TenantRepository(_db.Context);
        var tenant = Tenant.Create("Acme Corp", null);
        await tenantRepo.AddAsync(tenant);

        var repo = new TenantApplicationRepository(_db.Context);
        await repo.AddAsync(TenantApplication.Create(tenant.Id, "invoicing"));
        await repo.AddAsync(TenantApplication.Create(tenant.Id, "payroll"));

        tenant.Deactivate();
        await tenantRepo.UpdateAsync(tenant);

        Assert.False(await repo.IsSubscribedAsync(tenant.Id, "invoicing"));
        Assert.False(await repo.IsSubscribedAsync(tenant.Id, "payroll"));
    }

    [Fact]
    public async Task A_company_cannot_subscribe_to_one_application_twice()
    {
        var tenantId = await SeedTenantAsync();
        var repo = new TenantApplicationRepository(_db.Context);

        await repo.AddAsync(TenantApplication.Create(tenantId, "invoicing"));

        await Assert.ThrowsAnyAsync<DbUpdateException>(
            () => repo.AddAsync(TenantApplication.Create(tenantId, "invoicing")));
    }

    [Fact]
    public async Task Subscriptions_are_isolated_between_companies()
    {
        var acme = await SeedTenantAsync("Acme Corp");
        var globex = await SeedTenantAsync("Globex");
        var repo = new TenantApplicationRepository(_db.Context);

        await repo.AddAsync(TenantApplication.Create(acme, "invoicing"));

        Assert.True(await repo.IsSubscribedAsync(acme, "invoicing"));
        Assert.False(await repo.IsSubscribedAsync(globex, "invoicing"));
    }

    public void Dispose() => _db.Dispose();
}
