using Microsoft.EntityFrameworkCore;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Domain.Entities;
using PixSmith.Authorization.Repositories.Interfaces;

namespace PixSmith.Authorization.Repositories;

public sealed class TenantApplicationRepository(ApplicationDbContext context) : ITenantApplicationRepository
{
    public async Task<TenantApplication?> GetAsync(Guid tenantId, string clientId, CancellationToken ct = default)
    {
        var record = await context.TenantApplications
            .SingleOrDefaultAsync(a => a.TenantId == tenantId && a.ClientId == clientId, ct);

        return record is null ? null : ToDomain(record);
    }

    public async Task<IEnumerable<TenantApplication>> GetForTenantAsync(Guid tenantId, CancellationToken ct = default)
    {
        var records = await context.TenantApplications
            .Where(a => a.TenantId == tenantId)
            .OrderBy(a => a.ClientId)
            .ToListAsync(ct);

        return records.Select(ToDomain);
    }

    public async Task<IEnumerable<TenantApplication>> GetForClientAsync(string clientId, CancellationToken ct = default)
    {
        var records = await context.TenantApplications
            .Where(a => a.ClientId == clientId)
            .ToListAsync(ct);

        return records.Select(ToDomain);
    }

    public Task<bool> IsSubscribedAsync(Guid tenantId, string clientId, CancellationToken ct = default) =>
        // Both the subscription and the company must be active: deactivating a company has to
        // revoke access to every application without touching each subscription row.
        context.TenantApplications
            .AnyAsync(a => a.TenantId == tenantId
                        && a.ClientId == clientId
                        && a.IsActive
                        && context.Tenants.Any(t => t.Id == a.TenantId && t.IsActive), ct);

    public async Task AddAsync(TenantApplication subscription, CancellationToken ct = default)
    {
        context.TenantApplications.Add(new TenantApplicationRecord
        {
            Id = subscription.Id,
            TenantId = subscription.TenantId,
            ClientId = subscription.ClientId,
            IsActive = subscription.IsActive,
            CreatedAt = subscription.CreatedAt,
        });

        await context.SaveChangesAsync(ct);
    }

    public async Task UpdateAsync(TenantApplication subscription, CancellationToken ct = default)
    {
        var record = await context.TenantApplications
            .SingleOrDefaultAsync(a => a.Id == subscription.Id, ct);
        if (record is null) return;

        record.IsActive = subscription.IsActive;
        await context.SaveChangesAsync(ct);
    }

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        var record = await context.TenantApplications.SingleOrDefaultAsync(a => a.Id == id, ct);
        if (record is null) return;

        context.TenantApplications.Remove(record);
        await context.SaveChangesAsync(ct);
    }

    private static TenantApplication ToDomain(TenantApplicationRecord r) =>
        TenantApplication.Reconstitute(r.Id, r.TenantId, r.ClientId, r.IsActive, r.CreatedAt);
}
