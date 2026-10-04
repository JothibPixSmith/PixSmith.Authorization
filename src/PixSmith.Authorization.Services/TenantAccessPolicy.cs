using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PixSmith.Authorization.Repositories.Interfaces;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services;

public sealed class TenantAccessPolicy(
    ITenantContextResolver resolver,
    ITenantMembershipRepository memberships,
    ITenantRepository tenants,
    ITenantApplicationRepository subscriptions,
    IOptions<TenantEnforcementOptions> options,
    ILogger<TenantAccessPolicy> logger) : ITenantAccessPolicy
{
    public async Task<TenantAccessDecision> EvaluateForUserAsync(
        Guid userId, string? clientId, string? organization,
        IReadOnlyCollection<string>? platformRoles = null, CancellationToken ct = default)
    {
        var settings = options.Value;
        var context = await resolver.ResolveForUserAsync(userId, clientId, organization, ct);

        // Platform clients administer the auth server itself and are not tenant-scoped. They
        // are exempt from tenancy, not from authorization: platform authority is required in
        // its place, or any customer could authenticate to the vendor's admin console.
        if (settings.IsPlatformClient(clientId))
        {
            var holdsPlatformRole = platformRoles?.Any(r =>
                string.Equals(r, settings.PlatformClientRole, StringComparison.OrdinalIgnoreCase)) == true;

            if (!holdsPlatformRole)
            {
                logger.LogInformation(
                    "Access denied: user {UserId} lacks the '{Role}' platform role required by "
                    + "platform client '{ClientId}'.", userId, settings.PlatformClientRole, clientId);

                return TenantAccessDecision.Deny("You do not have access to this application.");
            }

            // A company context is still attached when one resolves, so an administrator who
            // is also a member gets the same claims as anywhere else.
            return TenantAccessDecision.Allow(context);
        }

        if (context is null)
            return TenantAccessDecision.Deny(await ExplainUnresolvedAsync(userId, organization, ct));

        // An individual denial overrides the company's subscription. Checked before the
        // subscription so a denied member gets the same answer whether or not their company
        // happens to subscribe — the reason is never disclosed to them.
        var membership = await memberships.GetAsync(context.TenantId, userId, ct);
        if (membership is not null && membership.IsDeniedApplication(clientId))
        {
            logger.LogInformation(
                "Access denied: user {UserId} is individually denied client '{ClientId}' in '{Tenant}'.",
                userId, clientId, context.Slug);

            return TenantAccessDecision.Deny("You do not have access to this application.");
        }

        // The nesting rule: access is derived from the company's subscription, never granted
        // to the user directly.
        if (!await subscriptions.IsSubscribedAsync(context.TenantId, clientId ?? string.Empty, ct))
        {
            logger.LogInformation(
                "Access denied: user {UserId} is a member of '{Tenant}', which is not subscribed " +
                "to client '{ClientId}'.", userId, context.Slug, clientId);

            return TenantAccessDecision.Deny(
                $"'{context.Name}' is not subscribed to this application.");
        }

        return TenantAccessDecision.Allow(context);
    }

    /// <summary>
    /// Turns an unresolved context into something the user can act on. Only ever describes
    /// the caller's own memberships — never reveals whether some other company exists.
    /// </summary>
    private async Task<string> ExplainUnresolvedAsync(
        Guid userId, string? organization, CancellationToken ct)
    {
        var active = new List<string>();

        foreach (var membership in await memberships.GetForUserAsync(userId, ct))
        {
            if (!membership.IsActive) continue;
            var tenant = await tenants.GetByIdAsync(membership.TenantId, ct);
            if (tenant is { IsActive: true }) active.Add(tenant.Slug);
        }

        if (active.Count == 0)
        {
            logger.LogInformation("Access denied: user {UserId} holds no active membership.", userId);
            return "Your account is not a member of any active organization.";
        }

        if (!string.IsNullOrWhiteSpace(organization))
        {
            logger.LogInformation(
                "Access denied: user {UserId} requested organization '{Organization}' without an " +
                "active membership of it.", userId, organization);
            return "You are not a member of the requested organization.";
        }

        // Several memberships and no choice made. Listing the caller's own organizations is
        // what makes this recoverable rather than a dead end.
        logger.LogInformation(
            "Access denied: user {UserId} belongs to {Count} organizations and specified none.",
            userId, active.Count);

        return "Specify which organization to sign in to using the 'organization' parameter. " +
               $"Yours: {string.Join(", ", active.Order())}.";
    }
}
