using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Domain.Entities;
using PixSmith.Authorization.Domain.Results;
using PixSmith.Authorization.Repositories.Interfaces;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services;

public sealed class TenantAccessService(
    ITenantRepository tenants,
    ITenantMembershipRepository memberships,
    ITenantApplicationRepository subscriptions,
    UserManager<IdentityUser<Guid>> userManager,
    IOpenIddictApplicationManager applicationManager) : ITenantAccessService
{
    // ── Memberships ──────────────────────────────────────────────────────────

    public async Task<Result<IEnumerable<TenantMemberDto>>> GetMembersAsync(
        Guid tenantId, CancellationToken ct = default)
    {
        if (await tenants.GetByIdAsync(tenantId, ct) is null)
            return Result<IEnumerable<TenantMemberDto>>.Failure("Tenant not found.");

        var records = (await memberships.GetForTenantAsync(tenantId, ct)).ToList();
        var dtos = new List<TenantMemberDto>(records.Count);

        foreach (var membership in records)
            dtos.Add(await ToMemberDtoAsync(membership));

        return Result<IEnumerable<TenantMemberDto>>.Success(dtos.OrderBy(d => d.Username));
    }

    public async Task<Result<IEnumerable<UserMembershipDto>>> GetMembershipsForUserAsync(
        Guid userId, CancellationToken ct = default)
    {
        var results = new List<UserMembershipDto>();

        foreach (var membership in await memberships.GetForUserAsync(userId, ct))
        {
            var tenant = await tenants.GetByIdAsync(membership.TenantId, ct);
            if (tenant is null) continue;   // company deleted mid-read; skip rather than fail

            results.Add(new UserMembershipDto(
                membership.Id, tenant.Id, tenant.Name, tenant.Slug, tenant.IsActive,
                membership.IsActive, [.. membership.Roles]));
        }

        return Result<IEnumerable<UserMembershipDto>>.Success(results.OrderBy(r => r.TenantName));
    }

    public async Task<Result<TenantMemberDto>> AddMemberAsync(
        Guid tenantId, AddTenantMemberRequest request, CancellationToken ct = default)
    {
        if (await tenants.GetByIdAsync(tenantId, ct) is null)
            return Result<TenantMemberDto>.Failure("Tenant not found.");

        // Verified before writing: a membership pointing at a non-existent user would grant
        // nothing but would sit in the table looking legitimate.
        if (await userManager.FindByIdAsync(request.UserId.ToString()) is null)
            return Result<TenantMemberDto>.Failure("User not found.");

        // The unique index would reject this anyway; catching it here turns a
        // DbUpdateException into a message an admin can act on.
        if (await memberships.GetAsync(tenantId, request.UserId, ct) is not null)
            return Result<TenantMemberDto>.Failure("This user is already a member of this tenant.");

        try
        {
            var membership = TenantMembership.Create(tenantId, request.UserId, request.Roles);
            await memberships.AddAsync(membership, ct);
            return Result<TenantMemberDto>.Success(await ToMemberDtoAsync(membership));
        }
        catch (Exception ex)
        {
            return Result<TenantMemberDto>.Failure(ex.Message);
        }
    }

    public async Task<Result> UpdateMemberAsync(
        Guid tenantId, Guid userId, UpdateTenantMemberRequest request, CancellationToken ct = default)
    {
        var membership = await memberships.GetAsync(tenantId, userId, ct);
        if (membership is null) return Result.Failure("Membership not found.");

        try
        {
            // Rebuilt from the request rather than mutated in place: the repository replaces
            // role sets wholesale, so a role absent from the request must actually be revoked.
            var replacement = TenantMembership.Reconstitute(
                membership.Id, tenantId, userId, request.IsActive, membership.CreatedAt,
                request.Roles ?? [],
                (request.ApplicationRoles ?? [])
                    .SelectMany(kvp => kvp.Value.Select(role => (kvp.Key, role))));

            await memberships.UpdateAsync(replacement, ct);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }

    public async Task<Result> RemoveMemberAsync(Guid tenantId, Guid userId, CancellationToken ct = default)
    {
        var membership = await memberships.GetAsync(tenantId, userId, ct);
        if (membership is null) return Result.Failure("Membership not found.");

        await memberships.DeleteAsync(membership.Id, ct);
        return Result.Success();
    }

    // ── Application subscriptions ────────────────────────────────────────────

    public async Task<Result<IEnumerable<TenantApplicationDto>>> GetApplicationsAsync(
        Guid tenantId, CancellationToken ct = default)
    {
        if (await tenants.GetByIdAsync(tenantId, ct) is null)
            return Result<IEnumerable<TenantApplicationDto>>.Failure("Tenant not found.");

        var records = (await subscriptions.GetForTenantAsync(tenantId, ct)).ToList();
        var dtos = new List<TenantApplicationDto>(records.Count);

        foreach (var subscription in records)
            dtos.Add(new TenantApplicationDto(
                subscription.Id, subscription.TenantId, subscription.ClientId,
                await DisplayNameAsync(subscription.ClientId, ct),
                subscription.IsActive, subscription.CreatedAt));

        return Result<IEnumerable<TenantApplicationDto>>.Success(dtos);
    }

    public async Task<Result<TenantApplicationDto>> AddApplicationAsync(
        Guid tenantId, AddTenantApplicationRequest request, CancellationToken ct = default)
    {
        if (await tenants.GetByIdAsync(tenantId, ct) is null)
            return Result<TenantApplicationDto>.Failure("Tenant not found.");

        if (string.IsNullOrWhiteSpace(request.ClientId))
            return Result<TenantApplicationDto>.Failure("A client id is required.");

        // Subscribing to a client that does not exist would silently grant nothing, and would
        // start granting access the day someone registers a client with that id.
        if (await applicationManager.FindByClientIdAsync(request.ClientId, ct) is null)
            return Result<TenantApplicationDto>.Failure(
                $"No OIDC application is registered with client id '{request.ClientId}'.");

        if (await subscriptions.GetAsync(tenantId, request.ClientId, ct) is not null)
            return Result<TenantApplicationDto>.Failure(
                "This tenant is already subscribed to that application.");

        try
        {
            var subscription = TenantApplication.Create(tenantId, request.ClientId);
            await subscriptions.AddAsync(subscription, ct);

            return Result<TenantApplicationDto>.Success(new TenantApplicationDto(
                subscription.Id, subscription.TenantId, subscription.ClientId,
                await DisplayNameAsync(subscription.ClientId, ct),
                subscription.IsActive, subscription.CreatedAt));
        }
        catch (Exception ex)
        {
            return Result<TenantApplicationDto>.Failure(ex.Message);
        }
    }

    public async Task<Result> UpdateApplicationAsync(
        Guid tenantId, string clientId, UpdateTenantApplicationRequest request, CancellationToken ct = default)
    {
        var subscription = await subscriptions.GetAsync(tenantId, clientId, ct);
        if (subscription is null) return Result.Failure("Subscription not found.");

        if (request.IsActive) subscription.Activate();
        else subscription.Deactivate();

        await subscriptions.UpdateAsync(subscription, ct);
        return Result.Success();
    }

    public async Task<Result> RemoveApplicationAsync(
        Guid tenantId, string clientId, CancellationToken ct = default)
    {
        var subscription = await subscriptions.GetAsync(tenantId, clientId, ct);
        if (subscription is null) return Result.Failure("Subscription not found.");

        await subscriptions.DeleteAsync(subscription.Id, ct);
        return Result.Success();
    }

    // ── Mapping ──────────────────────────────────────────────────────────────

    private async Task<TenantMemberDto> ToMemberDtoAsync(TenantMembership membership)
    {
        var user = await userManager.FindByIdAsync(membership.UserId.ToString());

        return new TenantMemberDto(
            membership.Id,
            membership.UserId,
            user?.UserName ?? "(deleted user)",
            user?.Email ?? string.Empty,
            membership.IsActive,
            [.. membership.Roles],
            membership.ApplicationRoles.ToDictionary(
                kvp => kvp.Key,
                kvp => (IReadOnlyList<string>)[.. kvp.Value]),
            membership.CreatedAt);
    }

    private async Task<string?> DisplayNameAsync(string clientId, CancellationToken ct)
    {
        var app = await applicationManager.FindByClientIdAsync(clientId, ct);
        return app is null ? null : await applicationManager.GetDisplayNameAsync(app, ct);
    }
}
