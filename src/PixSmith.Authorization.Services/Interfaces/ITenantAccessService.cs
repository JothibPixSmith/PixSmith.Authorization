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

    /// <summary>
    /// Adds an existing user to a company by email address — what self-service invitation needs,
    /// since an administrator knows a colleague's address rather than their id.
    ///
    /// <para>
    /// Fails distinguishably when no account exists, so the caller can tell "already a member"
    /// from "they need to register first". Issuing an email invitation to someone with no
    /// account is a further step and is not implemented.
    /// </para>
    /// </summary>
    Task<Result<TenantMemberDto>> InviteMemberByEmailAsync(
        Guid tenantId, InviteMemberRequest request, CancellationToken ct = default);
    Task<Result> UpdateMemberAsync(Guid tenantId, Guid userId, UpdateTenantMemberRequest request, CancellationToken ct = default);
    Task<Result> RemoveMemberAsync(Guid tenantId, Guid userId, CancellationToken ct = default);

    /// <summary>
    /// Bars or restores one member's access to one application, overriding the company's
    /// subscription. Use for a person who should not reach a particular system — suspending
    /// the subscription would remove it for every colleague too.
    /// </summary>
    Task<Result> SetMemberApplicationAccessAsync(
        Guid tenantId, Guid userId, string clientId,
        SetMemberApplicationAccessRequest request, CancellationToken ct = default);

    // ── Application subscriptions ────────────────────────────────────────────

    Task<Result<IEnumerable<TenantApplicationDto>>> GetApplicationsAsync(Guid tenantId, CancellationToken ct = default);
    Task<Result<TenantApplicationDto>> AddApplicationAsync(Guid tenantId, AddTenantApplicationRequest request, CancellationToken ct = default);
    Task<Result> UpdateApplicationAsync(Guid tenantId, string clientId, UpdateTenantApplicationRequest request, CancellationToken ct = default);
    Task<Result> RemoveApplicationAsync(Guid tenantId, string clientId, CancellationToken ct = default);
}
