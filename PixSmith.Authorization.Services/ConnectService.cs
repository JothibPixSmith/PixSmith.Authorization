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
    IOpenIddictScopeManager scopeManager) : IConnectService
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

        return Result.Failure(result.IsLockedOut
            ? "Account is locked out."
            : "Invalid credentials.");
    }

    // ── Identity building ─────────────────────────────────────────────────────

    public async Task<ClaimsIdentity> BuildIdentityAsync(
        IdentityUser<Guid> user,
        IEnumerable<string> requestedScopes,
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

        identity.SetScopes(requestedScopes);
        identity.SetResources(
            await scopeManager.ListResourcesAsync(identity.GetScopes(), ct).ToListAsync());
        identity.SetDestinations(GetDestinations);

        return identity;
    }

    public async Task<ClaimsIdentity> RefreshIdentityAsync(
        IdentityUser<Guid> user,
        ClaimsPrincipal existingPrincipal,
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

    // ── Destinations ──────────────────────────────────────────────────────────

    private static IEnumerable<string> GetDestinations(Claim claim) =>
        claim.Type switch
        {
            Claims.Name or Claims.Subject or Claims.Email or Claims.Role
                => [Destinations.AccessToken, Destinations.IdentityToken],
            _ => [Destinations.AccessToken]
        };
}
