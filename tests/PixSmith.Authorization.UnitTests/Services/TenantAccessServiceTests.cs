using Microsoft.AspNetCore.Identity;
using Moq;
using OpenIddict.Abstractions;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Domain.Entities;
using PixSmith.Authorization.Repositories;
using PixSmith.Authorization.Services;
using Xunit;

namespace PixSmith.Authorization.UnitTests.Services;

/// <summary>
/// Stage 2 of docs/MULTI-TENANCY.md — administration of memberships and subscriptions.
/// Still no authorization behaviour: nothing reads these tables at sign-in yet.
/// </summary>
public sealed class TenantAccessServiceTests : IDisposable
{
    private readonly SqliteTestDb _db = new();
    private readonly Mock<UserManager<IdentityUser<Guid>>> _users = MockUserManager();
    private readonly Mock<IOpenIddictApplicationManager> _apps = new();

    private TenantAccessService Build() => new(
        new TenantRepository(_db.Context),
        new TenantMembershipRepository(_db.Context),
        new TenantApplicationRepository(_db.Context),
        _users.Object,
        _apps.Object);

    private async Task<Guid> SeedTenantAsync(string name = "Acme Corp")
    {
        var tenant = Tenant.Create(name, null);
        await new TenantRepository(_db.Context).AddAsync(tenant);
        return tenant.Id;
    }

    private Guid SeedUser(string username = "alice")
    {
        // A real row as well as the mock: TenantMemberships has a foreign key to Users, so a
        // membership cannot reference a user that only exists in a mock.
        var id = _db.NewUser(username);

        _users.Setup(m => m.FindByIdAsync(id.ToString()))
              .ReturnsAsync(new IdentityUser<Guid> { Id = id, UserName = username, Email = $"{username}@x.com" });

        return id;
    }

    private void SeedClient(string clientId)
    {
        var app = new object();
        _apps.Setup(m => m.FindByClientIdAsync(clientId, It.IsAny<CancellationToken>()))
             .ReturnsAsync(app);
        _apps.Setup(m => m.GetDisplayNameAsync(app, It.IsAny<CancellationToken>()))
             .ReturnsAsync(clientId + " display");
    }

    // ── Members ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Adding_a_member_returns_the_user_details()
    {
        var tenantId = await SeedTenantAsync();
        var userId = SeedUser();

        var result = await Build().AddMemberAsync(tenantId, new AddTenantMemberRequest(userId, ["OrgAdmin"]));

        Assert.True(result.IsSuccess);
        Assert.Equal("alice", result.Value!.Username);
        Assert.Equal(["OrgAdmin"], result.Value.Roles);
    }

    [Fact]
    public async Task Adding_a_member_to_a_missing_tenant_fails()
    {
        var result = await Build().AddMemberAsync(Guid.NewGuid(), new AddTenantMemberRequest(SeedUser(), []));

        Assert.False(result.IsSuccess);
        Assert.Contains("Tenant not found", result.Error);
    }

    [Fact]
    public async Task Adding_a_non_existent_user_fails_before_writing()
    {
        // A membership row pointing at no user grants nothing but looks legitimate in the UI.
        var tenantId = await SeedTenantAsync();
        _users.Setup(m => m.FindByIdAsync(It.IsAny<string>())).ReturnsAsync((IdentityUser<Guid>?)null);

        var result = await Build().AddMemberAsync(tenantId, new AddTenantMemberRequest(Guid.NewGuid(), []));

        Assert.False(result.IsSuccess);
        Assert.Contains("User not found", result.Error);
        Assert.Empty(_db.Context.TenantMemberships);
    }

    [Fact]
    public async Task Adding_the_same_member_twice_gives_a_readable_error()
    {
        // The unique index would throw DbUpdateException; an admin needs a sentence instead.
        var tenantId = await SeedTenantAsync();
        var userId = SeedUser();
        var sut = Build();

        await sut.AddMemberAsync(tenantId, new AddTenantMemberRequest(userId, []));
        var second = await sut.AddMemberAsync(tenantId, new AddTenantMemberRequest(userId, []));

        Assert.False(second.IsSuccess);
        Assert.Contains("already a member", second.Error);
    }

    [Fact]
    public async Task Updating_a_member_revokes_roles_absent_from_the_request()
    {
        var tenantId = await SeedTenantAsync();
        var userId = SeedUser();
        var sut = Build();
        await sut.AddMemberAsync(tenantId, new AddTenantMemberRequest(userId, ["OrgAdmin", "Member"]));

        var update = await sut.UpdateMemberAsync(tenantId, userId,
            new UpdateTenantMemberRequest(true, ["Member"], []));

        Assert.True(update.IsSuccess);
        var members = (await sut.GetMembersAsync(tenantId)).Value!.ToList();
        Assert.Equal(["Member"], members.Single().Roles);
    }

    [Fact]
    public async Task Updating_a_member_persists_application_scoped_roles()
    {
        var tenantId = await SeedTenantAsync();
        var userId = SeedUser();
        var sut = Build();
        await sut.AddMemberAsync(tenantId, new AddTenantMemberRequest(userId, ["Member"]));

        await sut.UpdateMemberAsync(tenantId, userId, new UpdateTenantMemberRequest(
            true, ["Member"], new() { ["invoicing"] = ["Approver"] }));

        var member = (await sut.GetMembersAsync(tenantId)).Value!.Single();
        Assert.Equal(["Approver"], member.ApplicationRoles["invoicing"]);
    }

    [Fact]
    public async Task Removing_a_member_leaves_the_tenant_intact()
    {
        var tenantId = await SeedTenantAsync();
        var userId = SeedUser();
        var sut = Build();
        await sut.AddMemberAsync(tenantId, new AddTenantMemberRequest(userId, []));

        Assert.True((await sut.RemoveMemberAsync(tenantId, userId)).IsSuccess);
        Assert.Empty((await sut.GetMembersAsync(tenantId)).Value!);
        Assert.NotNull(await new TenantRepository(_db.Context).GetByIdAsync(tenantId));
    }

    [Fact]
    public async Task Memberships_for_a_user_span_companies()
    {
        var acme = await SeedTenantAsync("Acme Corp");
        var globex = await SeedTenantAsync("Globex");
        var userId = SeedUser();
        var sut = Build();

        await sut.AddMemberAsync(acme, new AddTenantMemberRequest(userId, ["OrgAdmin"]));
        await sut.AddMemberAsync(globex, new AddTenantMemberRequest(userId, ["Member"]));

        var memberships = (await sut.GetMembershipsForUserAsync(userId)).Value!.ToList();

        Assert.Equal(["Acme Corp", "Globex"], memberships.Select(m => m.TenantName));
    }

    // ── Subscriptions ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Subscribing_to_an_unregistered_client_is_refused()
    {
        // Otherwise the subscription silently grants nothing — and starts granting access
        // the day somebody registers a client with that id.
        var tenantId = await SeedTenantAsync();
        _apps.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
             .ReturnsAsync((object?)null);

        var result = await Build().AddApplicationAsync(tenantId, new AddTenantApplicationRequest("ghost-app"));

        Assert.False(result.IsSuccess);
        Assert.Contains("No OIDC application", result.Error);
    }

    [Fact]
    public async Task Subscribing_resolves_the_display_name()
    {
        var tenantId = await SeedTenantAsync();
        SeedClient("invoicing");

        var result = await Build().AddApplicationAsync(tenantId, new AddTenantApplicationRequest("invoicing"));

        Assert.True(result.IsSuccess);
        Assert.Equal("invoicing display", result.Value!.DisplayName);
    }

    [Fact]
    public async Task Subscribing_twice_gives_a_readable_error()
    {
        var tenantId = await SeedTenantAsync();
        SeedClient("invoicing");
        var sut = Build();

        await sut.AddApplicationAsync(tenantId, new AddTenantApplicationRequest("invoicing"));
        var second = await sut.AddApplicationAsync(tenantId, new AddTenantApplicationRequest("invoicing"));

        Assert.False(second.IsSuccess);
        Assert.Contains("already subscribed", second.Error);
    }

    [Fact]
    public async Task Suspending_a_subscription_is_reflected_in_the_listing()
    {
        var tenantId = await SeedTenantAsync();
        SeedClient("invoicing");
        var sut = Build();
        await sut.AddApplicationAsync(tenantId, new AddTenantApplicationRequest("invoicing"));

        await sut.UpdateApplicationAsync(tenantId, "invoicing", new UpdateTenantApplicationRequest(false));

        var apps = (await sut.GetApplicationsAsync(tenantId)).Value!.ToList();
        Assert.False(apps.Single().IsActive);
    }

    [Fact]
    public async Task Empty_client_id_is_refused()
    {
        var tenantId = await SeedTenantAsync();

        var result = await Build().AddApplicationAsync(tenantId, new AddTenantApplicationRequest("   "));

        Assert.False(result.IsSuccess);
        Assert.Contains("client id is required", result.Error);
    }

    public void Dispose() => _db.Dispose();

    private static Mock<UserManager<IdentityUser<Guid>>> MockUserManager() =>
        new(Mock.Of<IUserStore<IdentityUser<Guid>>>(), null!, null!, null!, null!, null!, null!, null!, null!);
}
