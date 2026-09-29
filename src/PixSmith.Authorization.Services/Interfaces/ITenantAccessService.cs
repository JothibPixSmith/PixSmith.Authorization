using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Domain.Results;

namespace PixSmith.Authorization.Services.Interfaces;

/// <summary>
/// Manages who belongs to a company and which applications that company subscribes to —
/// the two halves of the nested access model in docs/MULTI-TENANCY.md.
///
/// <para>
/// Both concerns live on one service because they answer one question together: what may
/// this person reach? Splitting them would mean two services that must always be consulted
/// as a pair.
/// </para>
/// </summary>
public interface ITenantAccessService
{
    // ── Memberships ──────────────────────────────────────────────────────────

    Task<Result<IEnumerable<TenantMemberDto>>> GetMembersAsync(Guid tenantId, CancellationToken ct = default);

    /// <summary>Every company a user belongs to. Backs the company picker in stage 5.</summary>
    Task<Result<IEnumerable<UserMembershipDto>>> GetMembershipsForUserAsync(Guid userId, CancellationToken ct = default);

    Task<Result<TenantMemberDto>> AddMemberAsync(Guid tenantId, AddTenantMemberRequest request, CancellationToken ct = default);
    Task<Result> UpdateMemberAsync(Guid tenantId, Guid userId, UpdateTenantMemberRequest request, CancellationToken ct = default);
    Task<Result> RemoveMemberAsync(Guid tenantId, Guid userId, CancellationToken ct = default);

    // ── Application subscriptions ────────────────────────────────────────────

    Task<Result<IEnumerable<TenantApplicationDto>>> GetApplicationsAsync(Guid tenantId, CancellationToken ct = default);
    Task<Result<TenantApplicationDto>> AddApplicationAsync(Guid tenantId, AddTenantApplicationRequest request, CancellationToken ct = default);
    Task<Result> UpdateApplicationAsync(Guid tenantId, string clientId, UpdateTenantApplicationRequest request, CancellationToken ct = default);
    Task<Result> RemoveApplicationAsync(Guid tenantId, string clientId, CancellationToken ct = default);
}
