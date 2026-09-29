using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Domain.Entities;
using PixSmith.Authorization.Repositories.Interfaces;

namespace PixSmith.Authorization.Services;

/// <summary>
/// Moves a pre-multi-tenancy instance onto the tenant model, once: creates a default
/// tenancy, makes every existing user a member of it, and subscribes it to every registered
/// application. Stage 3 of docs/MULTI-TENANCY.md.
///
/// <para>
/// This exists so that enforcement (stage 5) can be switched on unconditionally. Without a
/// backfill, an instance with zero memberships would refuse every authorization request; the
/// alternative — teaching the authorization path to skip its checks when no tenants exist —
/// is how enforcement quietly stops applying the day someone deletes the last tenant.
/// </para>
///
/// <para>
/// <b>This deliberately creates a tenancy without provisioning signatures.</b> That control
/// (docs/TENANT-PROVISIONING.md) guards the HTTP endpoints against an application provisioning
/// a tenancy for itself; it has never claimed to stop in-process code that already holds
/// database access, which is exactly why its trust anchor lives in configuration rather than
/// in the database. Keep this a one-time migration, not a reusable seeding capability.
/// </para>
/// </summary>
public sealed class TenantBackfillSeeder(
    IServiceProvider serviceProvider,
    IOptions<TenantBackfillOptions> options,
    ILogger<TenantBackfillSeeder> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken ct)
    {
        await using var scope = serviceProvider.CreateAsyncScope();

        var tenants = scope.ServiceProvider.GetRequiredService<ITenantRepository>();
        var memberships = scope.ServiceProvider.GetRequiredService<ITenantMembershipRepository>();
        var subscriptions = scope.ServiceProvider.GetRequiredService<ITenantApplicationRepository>();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        // Bounded to a registry that has never held a tenancy. Once any tenant exists —
        // whether this default one or a real customer — there is nothing sensible to migrate,
        // and re-running would sweep every user into a company they were removed from.
        if ((await tenants.GetAllAsync(ct)).Any())
        {
            logger.LogDebug("Tenant backfill skipped — the registry already contains a tenancy.");
            return;
        }

        var settings = options.Value;

        var userIds = await db.Users.Select(u => u.Id).ToListAsync(ct);
        if (userIds.Count == 0)
        {
            // A brand-new instance has nothing to migrate. It will gain tenancies through the
            // signed provisioning flow like any other, so creating an empty default here would
            // just be clutter that suppresses this seeder forever.
            logger.LogDebug("Tenant backfill skipped — no users exist yet.");
            return;
        }

        var tenant = Tenant.Create(settings.TenantName,
            "Created by the one-time multi-tenancy backfill (docs/MULTI-TENANCY.md).");
        await tenants.AddAsync(tenant, ct);

        // Platform admins keep administrative reach inside the tenancy they land in — after
        // this, that reach comes from the membership below, not from being staff.
        var adminIds = await (
            from userRole in db.UserRoles
            join role in db.Roles on userRole.RoleId equals role.Id
            where role.Name == "Admin"
            select userRole.UserId).Distinct().ToListAsync(ct);

        foreach (var userId in userIds)
        {
            var roles = new List<string> { settings.MemberRole };
            if (adminIds.Contains(userId) && !string.IsNullOrWhiteSpace(settings.AdminRole))
                roles.Add(settings.AdminRole);

            await memberships.AddAsync(TenantMembership.Create(tenant.Id, userId, roles), ct);
        }

        var clientIds = new List<string>();
        await foreach (var application in applications.ListAsync(cancellationToken: ct))
        {
            var clientId = await applications.GetClientIdAsync(application, ct);
            if (!string.IsNullOrWhiteSpace(clientId))
                clientIds.Add(clientId);
        }

        foreach (var clientId in clientIds)
            await subscriptions.AddAsync(TenantApplication.Create(tenant.Id, clientId), ct);

        logger.LogWarning(
            "Tenant backfill complete: created tenancy '{Tenant}' ({Slug}) with {Users} member(s) " +
            "({Admins} of them {AdminRole}) and {Clients} application subscription(s). " +
            "This ran without provisioning signatures because it is an in-process migration.",
            tenant.Name, tenant.Slug, userIds.Count, adminIds.Count, settings.AdminRole, clientIds.Count);
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
