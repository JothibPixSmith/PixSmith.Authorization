using AuthServer.Domain.Results;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services;

public sealed class AdminService(
    IUserService userService,
    IOAuthClientService clientService,
    UserManager<IdentityUser<Guid>> userManager,
    RoleManager<IdentityRole<Guid>> roleManager,
    ILogger<AdminService> logger) : IAdminService
{
    public async Task<Result<DashboardStatsDto>> GetDashboardStatsAsync(CancellationToken ct = default)
    {
        var usersResult = await userService.GetAllAsync(1, int.MaxValue, ct);
        if (!usersResult.IsSuccess)
            return Result<DashboardStatsDto>.Failure(usersResult.Error!);

        var all = usersResult.Value!.Items;

        var clientsResult = await clientService.GetAllAsync(ct);
        var clients = clientsResult.Value?.ToList() ?? [];

        var recentLogins = all
            .Where(u => u.LastLoginAt.HasValue)
            .OrderByDescending(u => u.LastLoginAt)
            .Take(10)
            .Select(u => new RecentLoginDto(u.Username, u.Email, u.LastLoginAt!.Value))
            .ToList();

        return Result<DashboardStatsDto>.Success(new DashboardStatsDto(
            TotalUsers:    all.Count,
            ActiveUsers:   all.Count(u => u.IsActive && !u.IsLocked),
            LockedUsers:   all.Count(u => u.IsLocked),
            TotalClients:  clients.Count,
            ActiveClients: clients.Count(c => c.IsActive),
            RecentLogins:  recentLogins));
    }

    public async Task<Result> AssignRoleAsync(
        Guid userId, string roleName, CancellationToken ct = default)
    {
        var domainResult = await userService.AssignRoleAsync(userId, roleName, ct);
        if (!domainResult.IsSuccess)
            return domainResult;

        // Ensure the Identity role exists before assigning
        if (!await roleManager.RoleExistsAsync(roleName))
            await roleManager.CreateAsync(new IdentityRole<Guid>(roleName));

        var identityUser = await userManager.FindByIdAsync(userId.ToString());
        if (identityUser is not null)
            await userManager.AddToRoleAsync(identityUser, roleName);

        logger.LogInformation("Assigned role {Role} to user {UserId}", roleName, userId);
        return Result.Success();
    }

    public async Task<Result> RemoveRoleAsync(
        Guid userId, string roleName, CancellationToken ct = default)
    {
        var domainResult = await userService.RemoveRoleAsync(userId, roleName, ct);
        if (!domainResult.IsSuccess)
            return domainResult;

        var identityUser = await userManager.FindByIdAsync(userId.ToString());
        if (identityUser is not null)
            await userManager.RemoveFromRoleAsync(identityUser, roleName);

        logger.LogInformation("Removed role {Role} from user {UserId}", roleName, userId);
        return Result.Success();
    }

    public async Task<Result> DeleteUserAsync(Guid userId, CancellationToken ct = default)
    {
        var identityUser = await userManager.FindByIdAsync(userId.ToString());
        if (identityUser is null)
            return Result.Failure("User not found.");

        var result = await userManager.DeleteAsync(identityUser);
        if (!result.Succeeded)
            return Result.Failure(string.Join("; ", result.Errors.Select(e => e.Description)));

        logger.LogInformation("Deleted user {UserId}", userId);
        return Result.Success();
    }

    public Task<Result<IEnumerable<RoleDto>>> GetRolesAsync(CancellationToken ct = default)
    {
        var roles = roleManager.Roles
            .OrderBy(r => r.Name)
            .Select(r => new RoleDto(r.Id, r.Name!))
            .AsEnumerable();

        return Task.FromResult(Result<IEnumerable<RoleDto>>.Success(roles));
    }

    public async Task<Result<RoleDto>> CreateRoleAsync(string name, CancellationToken ct = default)
    {
        if (await roleManager.RoleExistsAsync(name))
            return Result<RoleDto>.Failure($"Role '{name}' already exists.");

        var role = new IdentityRole<Guid>(name);
        var result = await roleManager.CreateAsync(role);
        if (!result.Succeeded)
            return Result<RoleDto>.Failure(string.Join("; ", result.Errors.Select(e => e.Description)));

        logger.LogInformation("Created role {Role}", name);
        return Result<RoleDto>.Success(new RoleDto(role.Id, role.Name!));
    }

    public async Task<Result> DeleteRoleAsync(string name, CancellationToken ct = default)
    {
        var role = await roleManager.FindByNameAsync(name);
        if (role is null)
            return Result.Failure("Role not found.");

        var usersInRole = await userManager.GetUsersInRoleAsync(name);
        if (usersInRole.Count > 0)
            return Result.Failure(
                $"Role '{name}' is still assigned to {usersInRole.Count} user(s). " +
                "Remove all assignments before deleting.");

        var result = await roleManager.DeleteAsync(role);
        if (!result.Succeeded)
            return Result.Failure(string.Join("; ", result.Errors.Select(e => e.Description)));

        logger.LogInformation("Deleted role {Role}", name);
        return Result.Success();
    }
}
