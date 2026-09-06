using PixSmith.Authorization.Domain.Results;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services;

public sealed class AccountService(
    IUserService userService,
    UserManager<IdentityUser<Guid>> userManager,
    IEmailService emailService,
    IConfiguration configuration,
    ILogger<AccountService> logger) : IAccountService
{
    public async Task<Result<UserDto>> RegisterAsync(
        RegisterUserRequest request, CancellationToken ct = default)
    {
        var domainResult = await userService.RegisterAsync(request, ct);
        if (!domainResult.IsSuccess)
            return Result<UserDto>.Failure(domainResult.Error!);

        var dto = domainResult.Value!;

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

        // Token requires the IdentityUser (security stamp) to exist, so this can only
        // happen here, after CreateAsync succeeds - not in UserService.RegisterAsync.
        var token = await userManager.GenerateEmailConfirmationTokenAsync(identityUser);
        var baseUri = (configuration["OpenIddict:BlazorClient:BaseUri"] ?? string.Empty).TrimEnd('/');
        var link = $"{baseUri}/confirm-email?email={Uri.EscapeDataString(request.Email)}&token={Uri.EscapeDataString(token)}";
        await emailService.SendEmailConfirmationAsync(request.Email, link, ct);

        logger.LogInformation("Registered user {Email}", request.Email);
        return Result<UserDto>.Success(dto);
    }
}
