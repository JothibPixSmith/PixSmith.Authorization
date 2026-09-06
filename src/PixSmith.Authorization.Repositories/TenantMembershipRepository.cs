using Microsoft.EntityFrameworkCore;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Domain.Entities;
using PixSmith.Authorization.Repositories.Interfaces;

namespace PixSmith.Authorization.Repositories;

public sealed class TenantMembershipRepository(ApplicationDbContext context) : ITenantMembershipRepository
{
    public async Task<TenantMembership?> GetAsync(Guid tenantId, Guid userId, CancellationToken ct = default)
    {
        var record = await context.TenantMemberships
            .SingleOrDefaultAsync(m => m.TenantId == tenantId && m.UserId == userId, ct);

        return record is null ? null : await HydrateAsync(record, ct);
    }

    public async Task<TenantMembership?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        var record = await context.TenantMemberships.SingleOrDefaultAsync(m => m.Id == id, ct);
        return record is null ? null : await HydrateAsync(record, ct);
    }

    public async Task<IEnumerable<TenantMembership>> GetForUserAsync(Guid userId, CancellationToken ct = default)
    {
        var records = await context.TenantMemberships
            .Where(m => m.UserId == userId)
            .ToListAsync(ct);

        return await HydrateManyAsync(records, ct);
    }

    public async Task<IEnumerable<TenantMembership>> GetForTenantAsync(Guid tenantId, CancellationToken ct = default)
    {
        var records = await context.TenantMemberships
            .Where(m => m.TenantId == tenantId)
            .ToListAsync(ct);

        return await HydrateManyAsync(records, ct);
    }

    public async Task AddAsync(TenantMembership membership, CancellationToken ct = default)
    {
        context.TenantMemberships.Add(new TenantMembershipRecord
        {
            Id = membership.Id,
            TenantId = membership.TenantId,
            UserId = membership.UserId,
            IsActive = membership.IsActive,
            CreatedAt = membership.CreatedAt,
        });

        WriteRoles(membership);
        await context.SaveChangesAsync(ct);
    }

    public async Task UpdateAsync(TenantMembership membership, CancellationToken ct = default)
    {
        var record = await context.TenantMemberships
            .SingleOrDefaultAsync(m => m.Id == membership.Id, ct);
        if (record is null) return;

        record.IsActive = membership.IsActive;

        // Roles are replaced wholesale rather than diffed. The sets are small, and a
        // replace cannot leave a stale grant behind the way a missed diff can.
        context.TenantMembershipRoles.RemoveRange(
            context.TenantMembershipRoles.Where(r => r.MembershipId == membership.Id));
        context.MembershipApplicationRoles.RemoveRange(
            context.MembershipApplicationRoles.Where(r => r.MembershipId == membership.Id));

        WriteRoles(membership);
        await context.SaveChangesAsync(ct);
    }

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        var record = await context.TenantMemberships.SingleOrDefaultAsync(m => m.Id == id, ct);
        if (record is null) return;

        // Role rows cascade from the FK configuration; removing the parent is enough.
        context.TenantMemberships.Remove(record);
        await context.SaveChangesAsync(ct);
    }

    // ── Mapping ──────────────────────────────────────────────────────────────

    private void WriteRoles(TenantMembership membership)
    {
        foreach (var role in membership.Roles)
        {
            context.TenantMembershipRoles.Add(new TenantMembershipRoleRecord
            {
                Id = Guid.NewGuid(),
                MembershipId = membership.Id,
                Role = role,
            });
        }

        foreach (var (clientId, roles) in membership.ApplicationRoles)
        {
            foreach (var role in roles)
            {
                context.MembershipApplicationRoles.Add(new MembershipApplicationRoleRecord
                {
                    Id = Guid.NewGuid(),
                    MembershipId = membership.Id,
                    ClientId = clientId,
                    Role = role,
                });
            }
        }
    }

    private async Task<TenantMembership> HydrateAsync(TenantMembershipRecord record, CancellationToken ct)
    {
        var roles = await context.TenantMembershipRoles
            .Where(r => r.MembershipId == record.Id)
            .Select(r => r.Role)
            .ToListAsync(ct);

        var appRoles = await context.MembershipApplicationRoles
            .Where(r => r.MembershipId == record.Id)
            .Select(r => new { r.ClientId, r.Role })
            .ToListAsync(ct);

        return TenantMembership.Reconstitute(
            record.Id, record.TenantId, record.UserId, record.IsActive, record.CreatedAt,
            roles, appRoles.Select(r => (r.ClientId, r.Role)));
    }

    /// <summary>
    /// Loads roles for a batch of memberships in two queries rather than two per membership —
    /// listing a company's members would otherwise be an N+1.
    /// </summary>
    private async Task<IEnumerable<TenantMembership>> HydrateManyAsync(
        List<TenantMembershipRecord> records, CancellationToken ct)
    {
        if (records.Count == 0) return [];

        var ids = records.Select(r => r.Id).ToList();

        var roles = (await context.TenantMembershipRoles
                .Where(r => ids.Contains(r.MembershipId))
                .Select(r => new { r.MembershipId, r.Role })
                .ToListAsync(ct))
            .GroupBy(r => r.MembershipId)
            .ToDictionary(g => g.Key, g => g.Select(r => r.Role).ToList());

        var appRoles = (await context.MembershipApplicationRoles
                .Where(r => ids.Contains(r.MembershipId))
                .Select(r => new { r.MembershipId, r.ClientId, r.Role })
                .ToListAsync(ct))
            .GroupBy(r => r.MembershipId)
            .ToDictionary(g => g.Key, g => g.Select(r => (r.ClientId, r.Role)).ToList());

        return records.Select(record => TenantMembership.Reconstitute(
            record.Id, record.TenantId, record.UserId, record.IsActive, record.CreatedAt,
            roles.GetValueOrDefault(record.Id, []),
            appRoles.GetValueOrDefault(record.Id, [])));
    }
}
