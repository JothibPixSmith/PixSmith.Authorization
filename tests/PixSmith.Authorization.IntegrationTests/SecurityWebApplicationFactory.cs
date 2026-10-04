using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Domain.Entities;
using PixSmith.Authorization.Repositories.Interfaces;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PixSmith.Authorization.IntegrationTests;

/// <summary>
/// Boots the real host for testing the security-critical paths over HTTP: tenancy
/// enforcement, the admin policy, and signed tenant provisioning.
///
/// <para>
/// These checks live at the seam between the controllers and the services. The unit suite
/// proves each policy correct in isolation, which says nothing about whether the endpoints
/// actually consult it — a refactor could drop the check and leave every unit test passing.
/// </para>
///
/// <para>
/// Runs as "Testing", not "Development", so OpenIddict keeps its transport-security
/// requirement exactly as production does; the client therefore uses an https base address.
/// Two provisioning keys are generated per factory instance so the signature quorum is
/// exercised with real ECDSA signatures rather than a stub.
/// </para>
/// </summary>
public sealed class SecurityWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");

    public const string AdminEmail = "admin@test.local";
    public const string AdminPassword = "Admin1234!";
    public const string UserPassword = "User1234!";

    /// <summary>Provisioning signing keys. Private halves never leave the test process.</summary>
    public ECDsa KeyA { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public ECDsa KeyB { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public const string KeyAId = "test-key-a";
    public const string KeyBId = "test-key-b";

    public SecurityWebApplicationFactory() => _connection.Open();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                // Seeds an administrator holding the platform Admin role.
                ["AdminSeed:Email"] = AdminEmail,
                ["AdminSeed:Username"] = "admin",
                ["AdminSeed:Password"] = AdminPassword,

                // The admin UI administers the server itself and is exempt from tenancy.
                ["TenantEnforcement:PlatformClients:0"] = "blazor-client",

                // A real two-of-two quorum.
                ["TenantProvisioning:RequiredSignatures"] = "2",
                ["TenantProvisioning:Keys:0:KeyId"] = KeyAId,
                ["TenantProvisioning:Keys:0:Holder"] = "Test Key A",
                ["TenantProvisioning:Keys:0:PublicKey"] = Convert.ToBase64String(KeyA.ExportSubjectPublicKeyInfo()),
                ["TenantProvisioning:Keys:1:KeyId"] = KeyBId,
                ["TenantProvisioning:Keys:1:Holder"] = "Test Key B",
                ["TenantProvisioning:Keys:1:PublicKey"] = Convert.ToBase64String(KeyB.ExportSubjectPublicKeyInfo()),

                // The backfill would otherwise sweep every seeded user into a default
                // tenancy and mask exactly what these tests are checking.
                ["TenantBackfill:TenantName"] = "Backfill (unused)",
            });
        });

        builder.ConfigureServices(services =>
        {
            var descriptor = services.SingleOrDefault(
                d => d.ServiceType == typeof(DbContextOptions<ApplicationDbContext>));
            if (descriptor is not null) services.Remove(descriptor);

            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlite(_connection, sqlite =>
                    sqlite.MigrationsAssembly("PixSmith.Authorization.DataContext.Migrations.Sqlite"));
                options.UseOpenIddict<Guid>();
            });
        });
    }

    /// <summary>https, because the host enforces transport security outside Development.</summary>
    public HttpClient CreateApiClient() => CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost/"),
        AllowAutoRedirect = false,
    });

    // ── Seeding, done through the real services rather than raw SQL ───────────

    public async Task<Guid> CreateUserAsync(string userName, string? platformRole = null)
    {
        using var scope = Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser<Guid>>>();

        var user = new IdentityUser<Guid>
        {
            Id = Guid.NewGuid(),
            UserName = userName,
            Email = $"{userName}@test.local",
            EmailConfirmed = true,   // SignIn.RequireConfirmedEmail is on
        };

        var result = await users.CreateAsync(user, UserPassword);
        if (!result.Succeeded)
            throw new InvalidOperationException(string.Join("; ", result.Errors.Select(e => e.Description)));

        if (platformRole is not null)
            await users.AddToRoleAsync(user, platformRole);

        return user.Id;
    }

    public async Task<Guid> CreateTenantAsync(string name)
    {
        using var scope = Services.CreateScope();
        var tenants = scope.ServiceProvider.GetRequiredService<ITenantRepository>();

        var tenant = Tenant.Create(name, null);
        await tenants.AddAsync(tenant);
        return tenant.Id;
    }

    public async Task AddMemberAsync(
        Guid tenantId, Guid userId, string[] roles, string? denyClientId = null)
    {
        using var scope = Services.CreateScope();
        var memberships = scope.ServiceProvider.GetRequiredService<ITenantMembershipRepository>();

        var membership = TenantMembership.Create(tenantId, userId, roles);
        if (denyClientId is not null) membership.DenyApplication(denyClientId, "denied by test");

        await memberships.AddAsync(membership);
    }

    public async Task DeactivateTenantAsync(Guid tenantId)
    {
        using var scope = Services.CreateScope();
        var tenants = scope.ServiceProvider.GetRequiredService<ITenantRepository>();

        var tenant = await tenants.GetByIdAsync(tenantId)
            ?? throw new InvalidOperationException("Tenant not found.");

        tenant.Deactivate();
        await tenants.UpdateAsync(tenant);
    }

    public async Task SubscribeAsync(Guid tenantId, string clientId)
    {
        using var scope = Services.CreateScope();
        var subscriptions = scope.ServiceProvider.GetRequiredService<ITenantApplicationRepository>();
        await subscriptions.AddAsync(TenantApplication.Create(tenantId, clientId));
    }

    public async Task RegisterClientAsync(
        string clientId, string[] grantTypes, string[] scopes,
        string? clientSecret = null, bool confidential = false)
    {
        using var scope = Services.CreateScope();
        var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            DisplayName = clientId,
            ClientType = confidential ? ClientTypes.Confidential : ClientTypes.Public,
            Permissions = { Permissions.Endpoints.Token },
        };

        foreach (var grant in grantTypes)
            descriptor.Permissions.Add(Permissions.Prefixes.GrantType + grant);
        foreach (var s in scopes)
            descriptor.Permissions.Add(Permissions.Prefixes.Scope + s);

        await apps.CreateAsync(descriptor);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing) return;

        _connection.Dispose();
        KeyA.Dispose();
        KeyB.Dispose();
    }
}
