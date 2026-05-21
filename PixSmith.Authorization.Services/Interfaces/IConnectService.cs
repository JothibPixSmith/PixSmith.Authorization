using AuthServer.Domain.Results;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace PixSmith.Authorization.Services.Interfaces;

public interface IConnectService
{
    /// <summary>Resolves a user from an OpenIddict principal's "sub" claim.</summary>
    Task<IdentityUser<Guid>?> FindUserBySubjectAsync(string subject, CancellationToken ct = default);

    /// <summary>Resolves a user from an ASP.NET Identity cookie principal.</summary>
    Task<IdentityUser<Guid>?> FindUserByIdentityPrincipalAsync(ClaimsPrincipal principal, CancellationToken ct = default);

    /// <summary>Finds a user by email, falling back to username.</summary>
    Task<IdentityUser<Guid>?> FindUserByUsernameAsync(string username, CancellationToken ct = default);

    /// <summary>
    /// Validates the password via Identity's sign-in manager (respects lockout).
    /// Returns Failure with a human-readable description on bad credentials or lockout.
    /// </summary>
    Task<Result> ValidatePasswordAsync(IdentityUser<Guid> user, string password, CancellationToken ct = default);

    /// <summary>
    /// Builds a fully populated ClaimsIdentity with scopes, resources, and per-claim
    /// destinations for the authorization-code and password grant flows.
    /// </summary>
    Task<ClaimsIdentity> BuildIdentityAsync(
        IdentityUser<Guid> user,
        IEnumerable<string> requestedScopes,
        CancellationToken ct = default);

    /// <summary>
    /// Rebuilds the ClaimsIdentity from an existing OpenIddict principal, refreshing
    /// user data from the database. Used for authorization-code and refresh-token flows.
    /// </summary>
    Task<ClaimsIdentity> RefreshIdentityAsync(
        IdentityUser<Guid> user,
        ClaimsPrincipal existingPrincipal,
        CancellationToken ct = default);

    /// <summary>
    /// Builds a ClaimsIdentity for a confidential client using the client-credentials grant.
    /// </summary>
    Task<ClaimsIdentity> BuildClientCredentialsIdentityAsync(
        string clientId,
        IEnumerable<string> requestedScopes,
        CancellationToken ct = default);

    /// <summary>Returns the userinfo payload for the /connect/userinfo endpoint.</summary>
    Task<Dictionary<string, object>?> GetUserInfoAsync(string subject, CancellationToken ct = default);

    /// <summary>Signs the current user out of the Identity cookie session.</summary>
    Task SignOutAsync(CancellationToken ct = default);
}
