using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.API;

public sealed class AdminUserSeeder(
    IServiceProvider serviceProvider,
    IConfiguration configuration,
    ILogger<AdminUserSeeder> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken ct)
    {
        var email    = configuration["AdminSeed:Email"];
        var password = configuration["AdminSeed:Password"];

        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
            return;

        await using var scope = serviceProvider.CreateAsyncScope();
        var userService    = scope.ServiceProvider.GetRequiredService<IUserService>();
        var accountService = scope.ServiceProvider.GetRequiredService<IAccountService>();
        var adminService   = scope.ServiceProvider.GetRequiredService<IAdminService>();

        // Only ever seed on a brand-new instance. Once any user exists, the seed config
        // (often left in plaintext env vars / user-secrets) must never be able to create
        // further accounts — that would be a standing way to mint accounts on a live system.
        var existingUsers = await userService.GetAllAsync(1, 1, ct);
        if (!existingUsers.IsSuccess || existingUsers.Value!.TotalCount > 0)
        {
            logger.LogDebug("Admin seed skipped — instance already has users.");
            return;
        }

        var username = configuration["AdminSeed:Username"] is { Length: > 0 } u
            ? u
            : email.Split('@')[0];

        // IUserService.RegisterAsync only creates the UserProfile — the IdentityUser row
        // (which AssignRoleAsync depends on) is created by IAccountService.RegisterAsync
        // via UserManager. Calling IUserService directly leaves a profile with no matching
        // IdentityUser, so role assignment fails with "User not found".
        var result = await accountService.RegisterAsync(
            new RegisterUserRequest(username, email, password, password, null, null), ct);

        if (!result.IsSuccess)
        {
            // Fail startup loudly: a configured-but-unusable AdminSeed would otherwise leave
            // the instance with no way to log in, and the cause (e.g. a password that doesn't
            // satisfy the Identity policy) would only ever surface as a buried log line.
            throw new InvalidOperationException(
                $"Admin seed failed for {email}: {result.Error}. " +
                "AdminSeed:Password must satisfy the Identity password policy " +
                "(8+ characters, an uppercase letter, a digit, and a special character). " +
                "Fix AdminSeed:Email/Username/Password and restart.");
        }

        var roleResult = await adminService.AssignRoleAsync(result.Value!.Id, "Admin", ct);
        if (!roleResult.IsSuccess)
            throw new InvalidOperationException(
                $"Admin user {email} was created but role assignment failed: {roleResult.Error}. " +
                "Fix the issue and restart — startup is blocked to avoid running with a broken admin account.");

        logger.LogInformation("Initial admin user {Email} created and assigned Admin role.", email);
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
