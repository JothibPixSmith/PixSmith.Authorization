using PixSmith.Authorization.Domain.Entities;

namespace PixSmith.Authorization.Repositories.Interfaces;

public interface ITenantApplicationRepository
{
    Task<TenantApplication?> GetAsync(Guid tenantId, string clientId, CancellationToken ct = default);

    Task<IEnumerable<TenantApplication>> GetForTenantAsync(Guid tenantId, CancellationToken ct = default);

    /// <summary>Every company subscribed to an application — used when retiring a client.</summary>
    Task<IEnumerable<TenantApplication>> GetForClientAsync(string clientId, CancellationToken ct = default);

    /// <summary>
    /// Whether a company holds an active subscription to an application. This is the check the
    /// authorization endpoint will make in stage 5, so it is kept to a single indexed lookup.
    /// </summary>
    Task<bool> IsSubscribedAsync(Guid tenantId, string clientId, CancellationToken ct = default);

    Task AddAsync(TenantApplication subscription, CancellationToken ct = default);
    Task UpdateAsync(TenantApplication subscription, CancellationToken ct = default);
    Task DeleteAsync(Guid id, CancellationToken ct = default);
}
