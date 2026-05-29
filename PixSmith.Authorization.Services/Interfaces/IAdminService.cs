using PixSmith.Authorization.Domain.Results;
using PixSmith.Authorization.DataContext;

namespace PixSmith.Authorization.Services.Interfaces;

public interface IAdminService
{
    Task<Result<DashboardStatsDto>> GetDashboardStatsAsync(CancellationToken ct = default);

    /// <summary>Assigns a role in both the domain model and ASP.NET Identity, creating the role if absent.</summary>
    Task<Result> AssignRoleAsync(Guid userId, string roleName, CancellationToken ct = default);

    /// <summary>Removes a role from both the domain model and ASP.NET Identity.</summary>
    Task<Result> RemoveRoleAsync(Guid userId, string roleName, CancellationToken ct = default);

    /// <summary>Deletes the Identity user (cascade removes logins, tokens, claims).</summary>
    Task<Result> DeleteUserAsync(Guid userId, CancellationToken ct = default);

    /// <summary>Admin override — updates username, email, name fields, and email confirmation state.</summary>
    Task<Result<UserDto>> UpdateUserAsync(Guid userId, AdminUpdateUserRequest request, CancellationToken ct = default);

    /// <summary>Admin override — resets password without requiring the current password.</summary>
    Task<Result> ResetPasswordAsync(Guid userId, string newPassword, CancellationToken ct = default);

    Task<Result<IReadOnlyList<ClaimDto>>> GetClaimsAsync(Guid userId, CancellationToken ct = default);
    Task<Result> AddClaimAsync(Guid userId, string type, string value, CancellationToken ct = default);
    Task<Result> RemoveClaimAsync(Guid userId, string type, string value, CancellationToken ct = default);

    Task<Result<IEnumerable<RoleDto>>> GetRolesAsync(CancellationToken ct = default);
    Task<Result<RoleDto>> CreateRoleAsync(string name, CancellationToken ct = default);

    /// <summary>Refuses deletion if any user is still assigned to the role.</summary>
    Task<Result> DeleteRoleAsync(string name, CancellationToken ct = default);
}
