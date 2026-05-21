using AuthServer.Domain.Results;
using Microsoft.AspNetCore.Identity;
using PixSmith.Authorization.DataContext;

namespace PixSmith.Authorization.Services.Interfaces;

public interface IAccountService
{
    /// <summary>
    /// Creates the domain user and the corresponding Identity user in one coordinated step.
    /// </summary>
    Task<Result<UserDto>> RegisterAsync(RegisterUserRequest request, CancellationToken ct = default);

    /// <summary>
    /// Finds or creates the domain user for an external SSO callback and links the
    /// Identity login so future sign-ins resolve without re-creating the account.
    /// </summary>
    Task<Result<UserDto>> LinkExternalLoginAsync(
        string provider, string providerKey, ExternalLoginInfo info,
        string email, string? firstName, string? lastName,
        CancellationToken ct = default);
}
