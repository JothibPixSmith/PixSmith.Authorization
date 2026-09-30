using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using PixSmith.Authorization.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PixSmith.Authorization.API.Security;

/// <summary>
/// Allows a company's own administrators to manage that company, without platform rights.
///
/// <para>
/// Authority comes from the caller's <b>token</b>: the <c>org_id</c> claim must match the
/// tenancy in the route, and the <c>roles</c> claim must contain <c>OrgAdmin</c>. Both are
/// stamped by the authorization server after verifying membership, so neither can be asserted
/// by the caller.
/// </para>
///
/// <para>
/// Matching <c>org_id</c> against the route is the whole point: without it an <c>OrgAdmin</c>
/// of one company could administer another. Platform administrators (holding the
/// <c>AdminAccess</c> policy) bypass this and may act on any tenancy.
/// </para>
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class AllowOrgAdminAttribute : Attribute, IFilterFactory
{
    /// <summary>Route parameter naming the tenancy being acted on.</summary>
    public string RouteParameter { get; init; } = "tenantId";

    /// <summary>Company role required within that tenancy.</summary>
    public string Role { get; init; } = "OrgAdmin";

    public bool IsReusable => false;

    public IFilterMetadata CreateInstance(IServiceProvider serviceProvider) =>
        ActivatorUtilities.CreateInstance<OrgAdminFilter>(serviceProvider, RouteParameter, Role);
}

public sealed class OrgAdminFilter(
    string routeParameter,
    string role,
    ILogger<OrgAdminFilter> logger) : IAsyncAuthorizationFilter
{
    public Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var user = context.HttpContext.User;

        // A platform administrator has already satisfied AdminAccess on the controller and may
        // act on any tenancy; nothing further to check.
        if (user.HasClaim(Claims.Role, "Admin") && user.HasClaim(Claims.Private.Scope, "admin"))
            return Task.CompletedTask;

        var claimed = user.FindFirst(TenantClaims.OrganizationId)?.Value;
        var routed = context.RouteData.Values[routeParameter]?.ToString();

        var sameCompany = Guid.TryParse(claimed, out var claimedId)
                          && Guid.TryParse(routed, out var routedId)
                          && claimedId == routedId;

        var holdsRole = user.FindAll(TenantClaims.Roles)
            .Any(c => string.Equals(c.Value, role, StringComparison.OrdinalIgnoreCase));

        if (sameCompany && holdsRole)
            return Task.CompletedTask;

        logger.LogInformation(
            "Org-scoped access denied: token org_id '{Claimed}' vs route '{Routed}', holds {Role}: {Holds}.",
            claimed, routed, role, holdsRole);

        // Deliberately uniform: an OrgAdmin of another company learns nothing about whether
        // the tenancy in the route exists.
        context.Result = new ObjectResult(new ProblemDetails
        {
            Status = StatusCodes.Status403Forbidden,
            Title = "Not permitted",
            Detail = $"Managing this organization requires the '{role}' role within it.",
            Instance = context.HttpContext.Request.Path,
        })
        { StatusCode = StatusCodes.Status403Forbidden };

        return Task.CompletedTask;
    }
}
