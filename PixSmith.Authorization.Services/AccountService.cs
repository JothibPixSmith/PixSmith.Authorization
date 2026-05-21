using AuthServer.Domain.Results;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services;

public sealed class AccountService(
    IUserService userService,
    UserManager<IdentityUser<Guid>> userManager,
    ILogger<AccountService> logger) : IAccountService
{
    public async Task<Result<UserDto>> RegisterAsync(
        RegisterUserRequest request, CancellationToken ct = default)
    {
        // Domain user (profile, roles, audit state)
        var domainResult = await userService.RegisterAsync(request, ct);
        if (!domainResult.IsSuccess)
            return Result<UserDto>.Failure(domainResult.Error!);

        var dto = domainResult.Value!;

        // Identity user (password hashing, lockout, claims infrastructure)
        var identityUser = new IdentityUser<Guid>
        {
            Id       = dto.Id,
            UserName = request.Username,
            Email    = request.Email,
        };

        var identityResult = await userManager.CreateAsync(identityUser, request.Password);
        if (!identityResult.Succeeded)
        {
            var error = string.Join("; ", identityResult.Errors.Select(e => e.Description));
            logger.LogWarning("Identity creation failed for {Email}: {Errors}", request.Email, error);
            return Result<UserDto>.Failure(error);
        }

        await userManager.AddToRoleAsync(identityUser, "User");

        logger.LogInformation("Registered user {Email}", request.Email);
        return Result<UserDto>.Success(dto);
    }

    public async Task<Result<UserDto>> LinkExternalLoginAsync(
        string provider, string providerKey, ExternalLoginInfo info,
        string email, string? firstName, string? lastName,
        CancellationToken ct = default)
    {
        // Find or create the domain user
        var userResult = await userService.FindOrCreateFromExternalLoginAsync(
            provider, providerKey, email, firstName, lastName, ct);

        if (!userResult.IsSuccess)
            return userResult;

        // Link to the Identity user so future ExternalLoginSignInAsync calls resolve it
        var identityUser = await userManager.FindByEmailAsync(email);
        if (identityUser is not null)
        {
            var existing = await userManager.GetLoginsAsync(identityUser);
            if (!existing.Any(l => l.LoginProvider == provider && l.ProviderKey == providerKey))
                await userManager.AddLoginAsync(identityUser, info);
        }

        logger.LogInformation("Linked {Provider} external login for {Email}", provider, email);
        return userResult;
    }
}
