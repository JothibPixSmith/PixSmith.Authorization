using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.Abstractions;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Domain.Entities;
using PixSmith.Authorization.Repositories;
using PixSmith.Authorization.Repositories.Interfaces;
using PixSmith.Authorization.Services;
using Xunit;

namespace PixSmith.Authorization.UnitTests.Services;

/// <summary>
/// Stage 3 of docs/MULTI-TENANCY.md — the one-time migration onto the tenant model.
/// The guards matter more than the happy path: re-running this on a live system would
/// sweep every user into a company they may have been removed from.
/// </summary>
public sealed class TenantBackfillSeederTests : IDisposable
{
    private readonly SqliteTestDb _db = new();
    private readonly Mock<IOpenIddictApplicationManager> _apps = new();

    private TenantBackfillSeeder Build(TenantBackfillOptions? options = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton(_db.Context);
        services.AddSingleton<ITenantRepository>(new TenantRepository(_db.Context));
        services.AddSingleton<ITenantMembershipRepository>(new TenantMembershipRepository(_db.Context));
        services.AddSingleton<ITenantApplicationRepository>(new TenantApplicationRepository(_db.Context));
        services.AddSingleton(_apps.Object);

        return new TenantBackfillSeeder(
            services.BuildServiceProvider(),
            Options.Create(options ?? new TenantBackfillOptions()),
            NullLogger<TenantBackfillSeeder>.Instance);
    }

    private Guid SeedUser(string name, bool platformAdmin = false)
    {
        var id = Guid.NewGuid();
        _db.Context.Users.Add(new IdentityUser<Guid>
        {
            Id = id, UserName = name, NormalizedUserName = name.ToUpperInvariant(),
            Email = $"{name}@x.com", NormalizedEmail = $"{name.ToUpperInvariant()}@X.COM",
        });

        if (platformAdmin)
        {
            var roleId = _db.Context.Roles.SingleOrDefault(r => r.Name == "Admin")?.Id;
            if (roleId is null)
            {
                roleId = Guid.NewGuid();
                _db.Context.Roles.Add(new IdentityRole<Guid>
                {
                    Id = roleId.Value, Name = "Admin", NormalizedName = "ADMIN",
                });
            }
            _db.Context.UserRoles.Add(new IdentityUserRole<Guid> { UserId = id, RoleId = roleId.Value });
        }

        _db.Context.SaveChanges();
        return id;
    }

    private void SeedClients(params string[] clientIds)
    {
        var objects = clientIds.Cast<object>().ToList();
        _apps.Setup(m => m.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()))
             .Returns(objects.ToAsyncEnumerable());
        foreach (var id in clientIds)
            _apps.Setup(m => m.GetClientIdAsync(id, It.IsAny<CancellationToken>()))
                 .ReturnsAsync(id);
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Creates_a_default_tenancy_with_every_user_and_client()
    {
        SeedUser("alice");
        SeedUser("bob");
        SeedClients("blazor-client", "m2m-client");

        await Build().StartAsync(default);

        var tenant = await _db.Context.Tenants.SingleAsync();
        Assert.Equal("Default", tenant.Name);
        Assert.Equal(2, await _db.Context.TenantMemberships.CountAsync());
        Assert.Equal(2, await _db.Context.TenantApplications.CountAsync());
    }

    [Fact]
    public async Task Every_migrated_user_gets_the_member_role()
    {
        SeedUser("alice");
        SeedClients();

        await Build().StartAsync(default);

        var roles = await _db.Context.TenantMembershipRoles.Select(r => r.Role).ToListAsync();
        Assert.Equal(["Member"], roles);
    }

    [Fact]
    public async Task Platform_admins_additionally_get_the_company_admin_role()
    {
        // Continuity: whoever administered the system before the migration can still
        // administer the tenancy they land in — but now via an explicit membership.
        var adminId = SeedUser("admin", platformAdmin: true);
        SeedUser("bob");
        SeedClients();

        await Build().StartAsync(default);

        var membership = await new TenantMembershipRepository(_db.Context)
            .GetAsync((await _db.Context.Tenants.SingleAsync()).Id, adminId);

        Assert.Equal(["Member", "OrgAdmin"], membership!.Roles.Order());

        var bobRoles = (await new TenantMembershipRepository(_db.Context)
            .GetForTenantAsync((await _db.Context.Tenants.SingleAsync()).Id))
            .Single(m => m.UserId != adminId).Roles;
        Assert.Equal(["Member"], bobRoles);
    }

    [Fact]
    public async Task Role_names_are_configurable()
    {
        SeedUser("alice", platformAdmin: true);
        SeedClients();

        await Build(new TenantBackfillOptions
        {
            TenantName = "Contoso", MemberRole = "Staff", AdminRole = "Owner",
        }).StartAsync(default);

        Assert.Equal("Contoso", (await _db.Context.Tenants.SingleAsync()).Name);
        Assert.Equal(["Owner", "Staff"],
            await _db.Context.TenantMembershipRoles.Select(r => r.Role).OrderBy(r => r).ToListAsync());
    }

    // ── Guards ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Does_nothing_when_a_tenancy_already_exists()
    {
        // The important guard. Re-running against a live system would sweep every user into
        // a company, including people deliberately removed from it.
        await new TenantRepository(_db.Context).AddAsync(Tenant.Create("Acme Corp", null));
        SeedUser("alice");
        SeedClients("blazor-client");

        await Build().StartAsync(default);

        Assert.Single(await _db.Context.Tenants.ToListAsync());
        Assert.Empty(await _db.Context.TenantMemberships.ToListAsync());
        Assert.Empty(await _db.Context.TenantApplications.ToListAsync());
    }

    [Fact]
    public async Task Does_nothing_on_a_brand_new_instance_with_no_users()
    {
        // A fresh install gains tenancies through the signed provisioning flow. Creating an
        // empty default here would be clutter that also suppresses this seeder forever.
        SeedClients("blazor-client");

        await Build().StartAsync(default);

        Assert.Empty(await _db.Context.Tenants.ToListAsync());
    }

    [Fact]
    public async Task Running_twice_is_a_no_op_the_second_time()
    {
        SeedUser("alice");
        SeedClients("blazor-client");

        var seeder = Build();
        await seeder.StartAsync(default);
        await seeder.StartAsync(default);

        Assert.Single(await _db.Context.Tenants.ToListAsync());
        Assert.Single(await _db.Context.TenantMemberships.ToListAsync());
        Assert.Single(await _db.Context.TenantApplications.ToListAsync());
    }

    [Fact]
    public async Task Migrated_state_satisfies_the_stage_5_subscription_check()
    {
        // What the backfill exists for: after it runs, an authorization request for a
        // pre-existing user and client would pass the checks stage 5 will add.
        var userId = SeedUser("alice");
        SeedClients("blazor-client");

        await Build().StartAsync(default);

        var tenantId = (await _db.Context.Tenants.SingleAsync()).Id;
        Assert.NotNull(await new TenantMembershipRepository(_db.Context).GetAsync(tenantId, userId));
        Assert.True(await new TenantApplicationRepository(_db.Context)
            .IsSubscribedAsync(tenantId, "blazor-client"));
    }

    public void Dispose() => _db.Dispose();
}
