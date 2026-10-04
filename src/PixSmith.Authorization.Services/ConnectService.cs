using PixSmith.Authorization.Domain.Results;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using PixSmith.Authorization.Services.Interfaces;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PixSmith.Authorization.Services;

public sealed class ConnectService(
    UserManager<IdentityUser<Guid>> userManager,
    SignInManager<IdentityUser<Guid>> signInManager,
    IOpenIddictApplicationManager applicationManager,
    IOpenIddictScopeManager scopeManager,
    ITenantContextResolver tenantContextResolver,
    ITenantAccessPolicy tenantAccessPolicy) : IConnectService
{
    // ── User resolution ───────────────────────────────────────────────────────

    public Task<IdentityUser<Guid>?> FindUserBySubjectAsync(
        string subject, CancellationToken ct = default) =>
        userManager.FindByIdAsync(subject);

    public Task<IdentityUser<Guid>?> FindUserByIdentityPrincipalAsync(
        ClaimsPrincipal principal, CancellationToken ct = default) =>
        userManager.GetUserAsync(principal);

    public async Task<IdentityUser<Guid>?> FindUserByUsernameAsync(
        string username, CancellationToken ct = default) =>
        await userManager.FindByEmailAsync(username)
        ?? await userManager.FindByNameAsync(username);

    // ── Credential validation ─────────────────────────────────────────────────

    public async Task<Result> ValidatePasswordAsync(
        IdentityUser<Guid> user, string password, CancellationToken ct = default)
    {
        var result = await signInManager.CheckPasswordSignInAsync(
            user, password, lockoutOnFailure: true);

        if (result.Succeeded) return Result.Success();

        if (result.IsLockedOut) return Result.Failure("Account is locked out.");
        if (result.IsNotAllowed) return Result.Failure("Please confirm your email address before signing in.");
        return Result.Failure("Invalid credentials.");
    }

    // ── Tenant access ─────────────────────────────────────────────────────────

    public async Task<TenantAccessDecision> AuthorizeTenantAccessAsync(
        IdentityUser<Guid> user, string? clientId, string? organization, CancellationToken ct = default)
    {
        var id = await userManager.GetUserIdAsync(user);

        if (!Guid.TryParse(id, out var userId))
            return TenantAccessDecision.Deny("The signed-in account could not be identified.");

        var platformRoles = (await userManager.GetRolesAsync(user)).ToList();

        return await tenantAccessPolicy.EvaluateForUserAsync(
            userId, clientId, organization, platformRoles, ct);
    }

    // ── Identity building ─────────────────────────────────────────────────────

    public async Task<ClaimsIdentity> BuildIdentityAsync(
        IdentityUser<Guid> user,
        IEnumerable<string> requestedScopes,
        string? clientId = null,
        TenantContext? context = null,
        CancellationToken ct = default)
    {
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType:           Claims.Name,
            roleType:           Claims.Role);

        identity.SetClaim(Claims.Subject, await userManager.GetUserIdAsync(user))
                .SetClaim(Claims.Email,   await userManager.GetEmailAsync(user))
                .SetClaim(Claims.Name,    await userManager.GetUserNameAsync(user));

        foreach (var role in await userManager.GetRolesAsync(user))
            identity.AddClaim(new Claim(Claims.Role, role));

        ApplyTenantContext(identity, context);

        identity.SetScopes(requestedScopes);
        identity.SetResources(
            await scopeManager.ListResourcesAsync(identity.GetScopes(), ct).ToListAsync());
        identity.SetDestinations(GetDestinations);

        return identity;
    }

    public async Task<ClaimsIdentity> RefreshIdentityAsync(
        IdentityUser<Guid> user,
        ClaimsPrincipal existingPrincipal,
        string? clientId = null,
        TenantContext? context = null,
        CancellationToken ct = default)
    {
        var identity = new ClaimsIdentity(
            existingPrincipal.Claims,
            TokenValidationParameters.DefaultAuthenticationType,
            Claims.Name, Claims.Role);

        identity.SetClaim(Claims.Subject, await userManager.GetUserIdAsync(user))
                .SetClaim(Claims.Email,   await userManager.GetEmailAsync(user))
                .SetClaim(Claims.Name,    await userManager.GetUserNameAsync(user));

        identity.RemoveClaims(Claims.Role);
        foreach (var role in await userManager.GetRolesAsync(user))
            identity.AddClaim(new Claim(Claims.Role, role));

        // Re-evaluated by the caller on every refresh rather than carried over from the old
        // principal. Without that, revoking a membership or a role would have no effect until
        // every outstanding refresh token expired.
        identity.RemoveClaims(TenantClaims.OrganizationId);
        identity.RemoveClaims(TenantClaims.OrganizationSlug);
        ApplyTenantContext(identity, context);

        identity.SetDestinations(GetDestinations);

        return identity;
    }

    public async Task<ClaimsIdentity> BuildClientCredentialsIdentityAsync(
        string clientId,
        IEnumerable<string> requestedScopes,
        CancellationToken ct = default)
    {
        var application = await applicationManager.FindByClientIdAsync(clientId, ct)
            ?? throw new InvalidOperationException($"Client application '{clientId}' not found.");

        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType:           Claims.Name,
            roleType:           Claims.Role);

        identity.SetClaim(Claims.Subject, await applicationManager.GetClientIdAsync(application, ct));
        identity.SetClaim(Claims.Name,    await applicationManager.GetDisplayNameAsync(application, ct));

        // A machine client belongs to one company; its context comes from the subscription
        // rather than from a membership, since there is no user.
        var machineContext = await tenantContextResolver.ResolveForClientAsync(clientId, ct);
        if (machineContext is not null)
        {
            identity.SetClaim(TenantClaims.OrganizationId, machineContext.TenantId.ToString())
                    .SetClaim(TenantClaims.OrganizationSlug, machineContext.Slug);
        }

        identity.SetScopes(requestedScopes);
        identity.SetResources(
            await scopeManager.ListResourcesAsync(identity.GetScopes(), ct).ToListAsync());
        identity.SetDestinations(GetDestinations);

        return identity;
    }

    // ── UserInfo payload ──────────────────────────────────────────────────────

    public async Task<Dictionary<string, object>?> GetUserInfoAsync(
        string subject, CancellationToken ct = default)
    {
        var user = await userManager.FindByIdAsync(subject);
        if (user is null) return null;

        var roles = await userManager.GetRolesAsync(user);

        return new Dictionary<string, object>
        {
            [Claims.Subject]       = await userManager.GetUserIdAsync(user),
            [Claims.Email]         = await userManager.GetEmailAsync(user) ?? string.Empty,
            [Claims.EmailVerified] = user.EmailConfirmed,
            [Claims.Name]          = await userManager.GetUserNameAsync(user) ?? string.Empty,
            [Claims.Role]          = roles,
        };
    }

    // ── Session ───────────────────────────────────────────────────────────────

    public Task SignOutAsync(CancellationToken ct = default) =>
        signInManager.SignOutAsync();

    // ── Tenant context ────────────────────────────────────────────────────────

    /// <summary>
    /// Stamps the company claims. A null context means none applies — a platform client, or a
    /// machine identity — and the claims are simply absent rather than the request failing.
    /// Whether absence is acceptable is the access policy's decision, not this method's.
    /// </summary>
    private static void ApplyTenantContext(ClaimsIdentity identity, TenantContext? context)
    {
        if (context is null) return;

        identity.SetClaim(TenantClaims.OrganizationId, context.TenantId.ToString())
                .SetClaim(TenantClaims.OrganizationSlug, context.Slug);

        // Company roles go in the plural `roles` claim (RFC 9068), leaving the singular
        // `role` claim carrying platform roles exactly as before.
        identity.RemoveClaims(TenantClaims.Roles);
        foreach (var role in context.Roles)
            identity.AddClaim(new Claim(TenantClaims.Roles, role));
    }

    // ── Destinations ──────────────────────────────────────────────────────────

    /// <summary>
    /// An allowlist: a claim not named here is silently dropped from the issued token, with no
    /// error anywhere. Any new claim must be added or it simply never arrives.
    /// </summary>
    private static IEnumerable<string> GetDestinations(Claim claim) =>
        claim.Type switch
        {
            Claims.Name or Claims.Subject or Claims.Email or Claims.Role
                => [Destinations.AccessToken, Destinations.IdentityToken],

            TenantClaims.OrganizationId or TenantClaims.OrganizationSlug or TenantClaims.Roles
                => [Destinations.AccessToken, Destinations.IdentityToken],

            _ => [Destinations.AccessToken]
        };
}
