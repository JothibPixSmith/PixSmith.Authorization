namespace PixSmith.Authorization.Services.Interfaces;

/// <summary>The company a token is being issued for, and the roles that apply within it.</summary>
public sealed record TenantContext(
    Guid TenantId,
    string Slug,
    string Name,
    IReadOnlyCollection<string> Roles);

/// <summary>
/// Works out which company a token should be issued for.
///
/// <para>
/// Returning <c>null</c> means "no company context could be established" — not "denied".
/// At stage 4 that simply omits the company claims; stage 5 is where an unresolved or
/// unauthorized context starts refusing the request. Keeping the distinction here means
/// enforcement can be switched on without also changing how resolution works.
/// </para>
/// </summary>
public interface ITenantContextResolver
{
    /// <param name="requestedOrganization">
    /// The <c>organization</c> authorization parameter, by tenant id or slug. When absent, a
    /// user belonging to exactly one company resolves to it; a user in several is ambiguous
    /// and resolves to null rather than to an arbitrary choice.
    /// </param>
    Task<TenantContext?> ResolveForUserAsync(
        Guid userId, string? clientId, string? requestedOrganization, CancellationToken ct = default);

    /// <summary>
    /// For the client-credentials grant, where there is no user. A machine client belongs to
    /// one company; if several subscribe to it the context is ambiguous and resolves to null.
    /// </summary>
    Task<TenantContext?> ResolveForClientAsync(string clientId, CancellationToken ct = default);
}
