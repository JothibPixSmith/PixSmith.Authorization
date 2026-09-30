using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Domain.Results;

namespace PixSmith.Authorization.Services.Interfaces;

/// <summary>
/// Manages OpenIddict scopes and the resources they map to.
///
/// <para>
/// A scope's resources become the <c>aud</c> claim of every token granted that scope, so this
/// is where audience isolation is actually configured. Scopes stored here work without being
/// listed in <c>RegisterScopes()</c> at startup, which is what lets a new application be
/// onboarded without a redeploy.
/// </para>
/// </summary>
public interface IOidcScopeService
{
    Task<Result<IReadOnlyList<OidcScopeDto>>> GetAllAsync(CancellationToken ct = default);
    Task<Result<OidcScopeDto>> GetByNameAsync(string name, CancellationToken ct = default);
    Task<Result<OidcScopeDto>> CreateAsync(CreateOidcScopeRequest request, CancellationToken ct = default);
    Task<Result> UpdateAsync(string name, UpdateOidcScopeRequest request, CancellationToken ct = default);
    Task<Result> DeleteAsync(string name, CancellationToken ct = default);
}
