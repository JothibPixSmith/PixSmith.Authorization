using PixSmith.Authorization.Domain.Entities;

namespace PixSmith.Authorization.Repositories.Interfaces;

public interface ITenantMembershipRepository
{
    Task<TenantMembership?> GetAsync(Guid tenantId, Guid userId, CancellationToken ct = default);
    Task<TenantMembership?> GetByIdAsync(Guid id, CancellationToken ct = default);

    /// <summary>Every company this person belongs to — the basis of the company picker.</summary>
    Task<IEnumerable<TenantMembership>> GetForUserAsync(Guid userId, CancellationToken ct = default);

    Task<IEnumerable<TenantMembership>> GetForTenantAsync(Guid tenantId, CancellationToken ct = default);

    Task AddAsync(TenantMembership membership, CancellationToken ct = default);

    /// <summary>Persists status and the full role sets, replacing what is stored.</summary>
    Task UpdateAsync(TenantMembership membership, CancellationToken ct = default);

    Task DeleteAsync(Guid id, CancellationToken ct = default);
}
