using Microsoft.EntityFrameworkCore;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Domain.Entities;
using PixSmith.Authorization.Repositories.Interfaces;

namespace PixSmith.Authorization.Repositories;

public sealed class TenantRepository(ApplicationDbContext context) : ITenantRepository
{
    public async Task<Tenant?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        var record = await context.Tenants.FindAsync([id], ct);
        return record is null ? null : ToTenant(record);
    }

    public async Task<IEnumerable<Tenant>> GetAllAsync(CancellationToken ct = default)
    {
        var records = await context.Tenants
            .OrderBy(t => t.Name)
            .ToListAsync(ct);
        return records.Select(ToTenant);
    }

    public async Task AddAsync(Tenant tenant, CancellationToken ct = default)
    {
        context.Tenants.Add(ToRecord(tenant));
        await context.SaveChangesAsync(ct);
    }

    public async Task UpdateAsync(Tenant tenant, CancellationToken ct = default)
    {
        var record = await context.Tenants.FindAsync([tenant.Id], ct);
        if (record is null) return;

        record.Name = tenant.Name;
        record.Slug = tenant.Slug;
        record.Description = tenant.Description;
        record.IsActive = tenant.IsActive;

        await context.SaveChangesAsync(ct);
    }

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        var record = await context.Tenants.FindAsync([id], ct);
        if (record is null) return;

        context.Tenants.Remove(record);
        await context.SaveChangesAsync(ct);
    }

    private static Tenant ToTenant(TenantRecord r) =>
        Tenant.Reconstitute(r.Id, r.Name, r.Slug, r.Description, r.IsActive, r.CreatedAt);

    private static TenantRecord ToRecord(Tenant t) => new()
    {
        Id = t.Id,
        Name = t.Name,
        Slug = t.Slug,
        Description = t.Description,
        IsActive = t.IsActive,
        CreatedAt = t.CreatedAt,
    };
}
