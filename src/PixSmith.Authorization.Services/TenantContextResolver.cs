using Microsoft.Extensions.Logging;
using PixSmith.Authorization.Domain.Entities;
using PixSmith.Authorization.Repositories.Interfaces;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services;

public sealed class TenantContextResolver(
    ITenantRepository tenants,
    ITenantMembershipRepository memberships,
    ITenantApplicationRepository subscriptions,
    ILogger<TenantContextResolver> logger) : ITenantContextResolver
{
    public async Task<TenantContext?> ResolveForUserAsync(
        Guid userId, string? clientId, string? requestedOrganization, CancellationToken ct = default)
    {
        // Only memberships that are themselves active and belong to an active company are
        // candidates — deactivating a company has to take effect without touching each
        // membership row.
        var candidates = new List<(TenantMembership Membership, Tenant Tenant)>();

        foreach (var membership in await memberships.GetForUserAsync(userId, ct))
        {
            if (!membership.IsActive) continue;

            var tenant = await tenants.GetByIdAsync(membership.TenantId, ct);
            if (tenant is { IsActive: true })
                candidates.Add((membership, tenant));
        }

        if (candidates.Count == 0)
        {
            logger.LogDebug("No active company membership for user {UserId}.", userId);
            return null;
        }

        (TenantMembership Membership, Tenant Tenant) chosen;

        if (!string.IsNullOrWhiteSpace(requestedOrganization))
        {
            var requested = requestedOrganization.Trim();

            var match = candidates.FirstOrDefault(c =>
                string.Equals(c.Tenant.Slug, requested, StringComparison.OrdinalIgnoreCase)
                || (Guid.TryParse(requested, out var id) && c.Tenant.Id == id));

            if (match.Tenant is null)
            {
                // The caller asked for a company this user is not an active member of. Stage 4
                // omits the claims; stage 5 turns this into access_denied.
                logger.LogDebug(
                    "User {UserId} requested organization '{Organization}' but holds no active " +
                    "membership of it.", userId, requested);
                return null;
            }

            chosen = match;
        }
        else if (candidates.Count == 1)
        {
            chosen = candidates[0];
        }
        else
        {
            // Picking one arbitrarily would issue a token whose authority the caller never
            // chose. Better to emit no company context and let the client ask explicitly.
            logger.LogDebug(
                "User {UserId} belongs to {Count} companies and sent no organization parameter.",
                userId, candidates.Count);
            return null;
        }

        return new TenantContext(
            chosen.Tenant.Id,
            chosen.Tenant.Slug,
            chosen.Tenant.Name,
            chosen.Membership.EffectiveRoles(clientId));
    }

    public async Task<TenantContext?> ResolveForClientAsync(string clientId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(clientId)) return null;

        var active = new List<Tenant>();

        foreach (var subscription in await subscriptions.GetForClientAsync(clientId, ct))
        {
            if (!subscription.IsActive) continue;

            var tenant = await tenants.GetByIdAsync(subscription.TenantId, ct);
            if (tenant is { IsActive: true })
                active.Add(tenant);
        }

        if (active.Count != 1)
        {
            logger.LogDebug(
                "Client '{ClientId}' is subscribed by {Count} active companies; no unambiguous " +
                "company context.", clientId, active.Count);
            return null;
        }

        // No user, so no membership roles — a machine identity's authority comes from its
        // scopes, not from roles held by a person.
        return new TenantContext(active[0].Id, active[0].Slug, active[0].Name, []);
    }
}
